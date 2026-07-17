//! A simple example using tokio-rustls to build an echo server.
//!
//! Data read by the server is written back to the client.
//!
//! The TLS handshake is performed via `TlsAcceptor::accept` (the default
//! path), or via `LazyConfigAcceptor` when `--lazy` is provided,
//! demonstrating access to the ClientHello before completing the handshake.

use std::error::Error as StdError;
use std::io;
use std::net::ToSocketAddrs;
use std::path::PathBuf;
use std::sync::Arc;

use argh::FromArgs;
use tokio::io::{AsyncWriteExt, copy, split};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::rustls::ServerConfig;
use tokio_rustls::rustls::pki_types::pem::PemObject;
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio_rustls::rustls::server::Acceptor;
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

    let config = Arc::new(
        ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(
                CertificateDer::pem_file_iter(&options.cert)?.collect::<Result<_, _>>()?,
                PrivateKeyDer::from_pem_file(&options.key)?,
            )?,
    );
    let acceptor = TlsAcceptor::from(config.clone());
    let listener = TcpListener::bind(&addr).await?;

    loop {
        let acceptor = acceptor.clone();
        let config = config.clone();
        let (stream, peer_addr) = listener.accept().await?;

        let fut = async move {
            let stream = match options.lazy {
                // Accept the connection lazily.
                true => accept_lazy(config, stream).await?,
                // Or, directly accept the stream.
                false => acceptor.accept(stream).await?,
            };

            let (mut reader, mut writer) = split(stream);
            let n = copy(&mut reader, &mut writer).await?;
            writer.flush().await?;
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

/// Tokio Rustls server example
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
}

/// Accept a TLS connection with `LazyConfigAcceptor`.
///
/// The handshake has two await points:
///
/// 1. reading the ClientHello
/// 2. driving the rest of the handshake with the chosen config
///
/// Between the two the ClientHello is available, e.g. for SNI-based config
/// selection.
async fn accept_lazy(
    config: Arc<ServerConfig>,
    stream: TcpStream,
) -> io::Result<TlsStream<TcpStream>> {
    let acceptor = LazyConfigAcceptor::new(Acceptor::default(), stream);
    tokio::pin!(acceptor);

    // Read the ClientHello.
    let start = acceptor.as_mut().await?;

    // The ClientHello is now available, e.g. for SNI-based config selection.
    if let Some(sni) = start.client_hello().server_name() {
        println!("ClientHello with SNI: {sni}");
    }

    // Complete the handshake.
    start.into_stream(config).await
}
