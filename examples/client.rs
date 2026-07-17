//! An example using tokio-rustls to make an HTTP GET request, demonstrating
//! how to apply timeouts to every phase of the connection lifecycle using
//! only `tokio::time` and the public tokio-rustls API:
//!
//! * TCP connect
//! * TLS handshake
//! * individual reads/writes on the established stream
//! * graceful TLS shutdown (close notify)
//!
//! The handshake timeout also applies unchanged to `TlsConnector::connect_with`
//! and `TlsConnectorWithAlpn::connect`, they all return the same `Connect`
//! future.

use std::error::Error as StdError;
use std::future::Future;
use std::io;
use std::net::ToSocketAddrs;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use argh::FromArgs;
use tokio::io::{AsyncReadExt, AsyncWriteExt, stdout as tokio_stdout};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;
use tokio_rustls::rustls::pki_types::pem::PemObject;
use tokio_rustls::rustls::pki_types::{CertificateDer, ServerName};
use tokio_rustls::rustls::{ClientConfig, RootCertStore};

#[tokio::main]
async fn main() -> Result<(), Box<dyn StdError + Send + Sync + 'static>> {
    let options: Options = argh::from_env();

    let addr = (options.host.as_str(), options.port)
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| io::Error::from(io::ErrorKind::NotFound))?;
    let domain = options.domain.unwrap_or(options.host);
    let content = format!("GET / HTTP/1.0\r\nHost: {domain}\r\n\r\n",);

    let mut root_cert_store = RootCertStore::empty();
    if let Some(cafile) = &options.cafile {
        for cert in CertificateDer::pem_file_iter(cafile)? {
            root_cert_store.add(cert?)?;
        }
    } else {
        root_cert_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    }

    let connector = TlsConnector::from(Arc::new(
        ClientConfig::builder()
            .with_root_certificates(root_cert_store)
            .with_no_client_auth(),
    ));

    // TCP connect, bounded by the connect timeout.
    let stream = with_timeout(
        TcpStream::connect(&addr),
        "TCP connect",
        Duration::from_secs(options.connect_timeout),
    )
    .await?;

    // TLS handshake, bounded by the handshake timeout.
    //
    // On timeout the `Connect` future, and the socket it owns, is dropped.
    let domain = ServerName::try_from(domain.as_str())?.to_owned();
    let mut stream = with_timeout(
        connector.connect(domain, stream),
        "TLS handshake",
        Duration::from_secs(options.handshake_timeout),
    )
    .await?;

    let io_timeout = Duration::from_secs(options.io_timeout);

    // request/response, with a timeout on each individual write and
    // read.
    //
    // Note a single `timeout()` around `read_to_end()` would bound the
    // *total* response time instead. Wrapping each `read()` bounds idle time.
    with_timeout(
        stream.write_all(content.as_bytes()),
        "request write",
        io_timeout,
    )
    .await?;

    let mut stdout = tokio_stdout();
    let mut buf = vec![0u8; 8192];
    loop {
        let n = with_timeout(stream.read(&mut buf), "response read", io_timeout).await?;
        if n == 0 {
            break;
        }
        stdout.write_all(&buf[..n]).await?;
    }
    stdout.flush().await?;

    // graceful TLS shutdown.
    //
    // `shutdown()` writes a close_notify alert, so it too can block on a stalled peer.
    with_timeout(
        stream.shutdown(),
        "TLS shutdown",
        Duration::from_secs(options.shutdown_timeout),
    )
    .await?;

    Ok(())
}

/// Tokio Rustls client example with timeouts
#[derive(FromArgs)]
struct Options {
    /// host
    #[argh(positional)]
    host: String,

    /// port
    #[argh(option, short = 'p', default = "443")]
    port: u16,

    /// domain
    #[argh(option, short = 'd')]
    domain: Option<String>,

    /// cafile
    #[argh(option, short = 'c')]
    cafile: Option<PathBuf>,

    /// TCP connect timeout (seconds)
    #[argh(option, default = "10")]
    connect_timeout: u64,

    /// TLS handshake timeout (seconds)
    #[argh(option, default = "10")]
    handshake_timeout: u64,

    /// per-read/write timeout on the established stream (seconds)
    #[argh(option, default = "30")]
    io_timeout: u64,

    /// graceful TLS shutdown (close_notify) timeout (seconds)
    #[argh(option, default = "5")]
    shutdown_timeout: u64,
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
