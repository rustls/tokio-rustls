//! An example using tokio-rustls to build an echo server, demonstrating how
//! to apply timeouts to every phase of each accepted connection.
//!
//! * TLS handshake via `TlsAcceptor::accept` (the default path)
//! * TLS handshake via `LazyConfigAcceptor` (`--lazy`), with one deadline
//!   spanning both the wait for the ClientHello and the rest of the
//!   handshake, and `take_io()` used to answer a stalled client in plaintext
//! * individual reads/writes on the established stream
//! * graceful TLS shutdown (close notify)

use std::error::Error as StdError;
use std::future::Future;
use std::io;
use std::net::ToSocketAddrs;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use argh::FromArgs;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::{Instant, timeout, timeout_at};
use tokio_rustls::rustls::crypto::Identity;
use tokio_rustls::rustls::pki_types::pem::PemObject;
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio_rustls::rustls::{self, ServerConfig};
use tokio_rustls::server::TlsStream;
use tokio_rustls::{LazyConfigAcceptor, TlsAcceptor};

#[tokio::main]
async fn main() -> Result<(), Box<dyn StdError + Send + Sync + 'static>> {
    let options: Options = argh::from_env();

    let addr = options
        .addr
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| io::Error::from(io::ErrorKind::AddrNotAvailable))?;

    let handshake_timeout = Duration::from_secs(options.handshake_timeout);
    let io_timeout = Duration::from_secs(options.io_timeout);
    let shutdown_timeout = Duration::from_secs(options.shutdown_timeout);

    let certs = CertificateDer::pem_file_iter(&options.cert)?.collect::<Result<Vec<_>, _>>()?;
    let identity = Arc::new(Identity::from_cert_chain(certs)?);
    let config = Arc::new(
        ServerConfig::builder(provider())
            .with_no_client_auth()
            .with_single_cert(identity, PrivateKeyDer::from_pem_file(&options.key)?)?,
    );
    let acceptor = TlsAcceptor::from(config.clone());
    let listener = TcpListener::bind(&addr).await?;

    loop {
        let acceptor = acceptor.clone();
        let config = config.clone();
        let (stream, peer_addr) = listener.accept().await?;

        let fut = async move {
            let stream = match options.lazy {
                // Accept the connection lazily, applying the handshake_timeout.
                true => accept_lazy(config, stream, handshake_timeout).await?,
                // Or, directly accept the stream, applying the handshake_timeout.
                false => {
                    with_timeout(acceptor.accept(stream), "TLS handshake", handshake_timeout)
                        .await?
                }
            };

            let n = serve(stream, io_timeout, shutdown_timeout).await?;
            println!("Echo: {} - {}", peer_addr, n);

            Ok(()) as io::Result<()>
        };

        tokio::spawn(async move {
            if let Err(err) = fut.await {
                eprintln!("{peer_addr}: {err:?}");
            }
        });
    }
}

/// Tokio Rustls server example with timeouts
#[derive(FromArgs)]
struct Options {
    /// bind addr
    #[argh(positional)]
    addr: String,

    /// cert file
    #[argh(option, short = 'c')]
    cert: PathBuf,

    /// key file
    #[argh(option, short = 'k')]
    key: PathBuf,

    /// use LazyConfigAcceptor instead of TlsAcceptor
    #[argh(switch, short = 'l')]
    lazy: bool,

    /// TLS handshake timeout (seconds)
    #[argh(option, default = "5")]
    handshake_timeout: u64,

    /// per-read/write timeout on the established stream (seconds)
    #[argh(option, default = "30")]
    io_timeout: u64,

    /// graceful TLS shutdown (close_notify) timeout (seconds)
    #[argh(option, default = "5")]
    shutdown_timeout: u64,
}

/// Accept a TLS connection with `LazyConfigAcceptor` under a single deadline.
///
/// The handshake has two await points:
///
/// 1. reading the ClientHello
/// 2. driving the rest of the handshake with the chosen config
///
/// A shared `Instant` deadline (via `timeout_at`) keeps the total bounded
/// rather than granting each phase its own budget.
///
/// If the client stalls before even sending a ClientHello we can take the
/// socket back with `take_io()` and respond in plaintext before hanging up.
async fn accept_lazy(
    config: Arc<ServerConfig>,
    stream: TcpStream,
    handshake_timeout: Duration,
) -> io::Result<TlsStream<TcpStream>> {
    let deadline = Instant::now() + handshake_timeout;

    let acceptor = LazyConfigAcceptor::new(stream);
    tokio::pin!(acceptor);

    // Read the ClientHello, respecting the deadline.
    let start = match timeout_at(deadline, acceptor.as_mut()).await {
        Ok(result) => result?,
        Err(_) => {
            // No ClientHello arrived in time. No TLS handshake has happened yet,
            // so we can still answer in plaintext.
            if let Some(mut stream) = acceptor.take_io() {
                let _ = stream
                    .write_all(b"HTTP/1.0 408 Request Timeout\r\n\r\n")
                    .await;
            }
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                format!("timed out awaiting ClientHello after {handshake_timeout:?}"),
            ));
        }
    };

    // The ClientHello is now available, e.g. for SNI-based config selection.
    if let Some(sni) = start.client_hello().server_name() {
        println!("ClientHello with SNI: {}", sni.as_ref());
    }

    // Complete the handshake, respecting the deadline.
    match timeout_at(deadline, start.into_stream(config)).await {
        Ok(result) => result,
        Err(_elapsed) => Err(io::Error::new(
            io::ErrorKind::TimedOut,
            format!("TLS handshake timed out after {handshake_timeout:?}"),
        )),
    }
}

/// Serve a single established TLS `stream`, respecting timeouts.
///
/// Echoes one request worth of bytes, bounding each read/write with the `io_timeout`, and the
/// final graceful shutdown with the `shutdown_timeout.`
async fn serve<IO: AsyncRead + AsyncWrite + Unpin>(
    mut stream: TlsStream<IO>,
    io_timeout: Duration,
    shutdown_timeout: Duration,
) -> io::Result<u64> {
    let mut echoed = 0;
    let mut buf = vec![0u8; 8192];
    loop {
        // Bounding each read() limits how long the peer may sit idle. A
        // single timeout() around the whole loop would bound total
        // connection time instead.
        // For an idle peer, stop echoing and fall through to the graceful
        // shutdown below so the peer sees close_notify rather than an abrupt
        // close.
        let n = match timeout(io_timeout, stream.read(&mut buf)).await {
            Ok(result) => result?,
            Err(_elapsed) => break,
        };
        if n == 0 {
            break;
        }
        with_timeout(stream.write_all(&buf[..n]), "write", io_timeout).await?;
        echoed += n as u64;
    }
    with_timeout(stream.flush(), "flush", io_timeout).await?;

    // shutdown() writes a close_notify alert, so it too can block on a
    // stalled peer.
    with_timeout(stream.shutdown(), "TLS shutdown", shutdown_timeout).await?;
    Ok(echoed)
}

/// Await `fut` for at most `duration`, converting an elapsed timeout into an `io::Error`.
///
/// On timeout, the returned error describes the `phase` that timed out.
async fn with_timeout<T>(
    fut: impl Future<Output = io::Result<T>>,
    phase: &str,
    duration: Duration,
) -> io::Result<T> {
    match timeout(duration, fut).await {
        Ok(result) => result,
        Err(_) => Err(io::Error::new(
            io::ErrorKind::TimedOut,
            format!("{phase} timed out after {duration:?}"),
        )),
    }
}

fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    #[cfg(feature = "aws_lc_rs")]
    {
        Arc::new(rustls_aws_lc_rs::DEFAULT_PROVIDER.clone())
    }

    #[cfg(all(not(feature = "aws_lc_rs"), feature = "ring"))]
    {
        Arc::new(rustls_ring::DEFAULT_PROVIDER.clone())
    }

    #[cfg(not(any(feature = "aws_lc_rs", feature = "ring")))]
    {
        panic!("enable either the `aws_lc_rs` or `ring` feature")
    }
}
