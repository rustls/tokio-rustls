#![cfg(feature = "early-data")]

use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpListener};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::thread;

use futures_util::FutureExt as _;
use rustls::pki_types::ServerName;
use rustls::{self, ClientConfig, Connection as _, ServerConnection, VecInput};
use rustls_util::{Stream, complete_io};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;

async fn send<S: AsyncRead + AsyncWrite + Unpin>(
    config: Arc<ClientConfig>,
    addr: SocketAddr,
    wrapper: impl Fn(TcpStream) -> S,
    data: &[u8],
    vectored: bool,
) -> io::Result<(TlsStream<S>, Vec<u8>)> {
    let connector = TlsConnector::from(config).early_data(true);
    let stream = wrapper(TcpStream::connect(&addr).await?);
    let domain = ServerName::try_from("foobar.com").unwrap();

    let mut stream = connector.connect(domain, stream).await?;
    utils::write(&mut stream, data, vectored).await?;
    stream.flush().await?;
    stream.shutdown().await?;

    let mut buf = Vec::new();
    stream.read_to_end(&mut buf).await?;

    Ok((stream, buf))
}

#[tokio::test]
async fn test_0rtt() -> io::Result<()> {
    test_0rtt_impl(|s| s, false).await
}

#[tokio::test]
async fn test_0rtt_vectored() -> io::Result<()> {
    test_0rtt_impl(|s| s, true).await
}

#[tokio::test]
async fn test_0rtt_vectored_flush_pending() -> io::Result<()> {
    test_0rtt_impl(utils::FlushWrapper::new, false).await
}

async fn test_0rtt_impl<S: AsyncRead + AsyncWrite + Unpin>(
    wrapper: impl Fn(TcpStream) -> S,
    vectored: bool,
) -> io::Result<()> {
    let (client, addr) = start_server(8192)?;

    let (io, buf) = send(client.clone(), addr, &wrapper, b"hello", vectored).await?;
    assert!(!io.get_ref().1.is_early_data_accepted());
    assert_eq!("LATE:hello", String::from_utf8_lossy(&buf));

    let (io, buf) = send(client, addr, wrapper, b"world!", vectored).await?;
    assert!(io.get_ref().1.is_early_data_accepted());
    assert_eq!("EARLY:world!LATE:", String::from_utf8_lossy(&buf));

    Ok(())
}

fn start_server(max_early_data_size: u32) -> io::Result<(Arc<ClientConfig>, SocketAddr)> {
    let (mut server, mut client) = utils::make_configs();
    server.max_early_data_size = max_early_data_size;
    let server = Arc::new(server);

    let listener = TcpListener::bind("127.0.0.1:0")?;
    let server_port = listener.local_addr().unwrap().port();
    thread::spawn(move || {
        loop {
            let (mut sock, _addr) = listener.accept().unwrap();

            let server = Arc::clone(&server);
            thread::spawn(move || {
                let mut conn = ServerConnection::new(server).unwrap();
                let mut input = VecInput::default();
                let mut received_plaintext = Vec::new();
                let mut output = Vec::new();
                complete_io(
                    &mut sock,
                    &mut input,
                    &mut received_plaintext,
                    &mut output,
                    &mut conn,
                )
                .unwrap();

                if let Some(mut early_data) = conn.early_data() {
                    let mut buf = Vec::new();
                    early_data.read_to_end(&mut buf).unwrap();
                    let mut stream = Stream::new(
                        &mut input,
                        &mut received_plaintext,
                        &mut output,
                        &mut conn,
                        &mut sock,
                    );
                    stream.write_all(b"EARLY:").unwrap();
                    stream.write_all(&buf).unwrap();
                }

                {
                    let mut stream = Stream::new(
                        &mut input,
                        &mut received_plaintext,
                        &mut output,
                        &mut conn,
                        &mut sock,
                    );
                    stream.write_all(b"LATE:").unwrap();
                    loop {
                        let mut buf = [0; 1024];
                        let n = stream.read(&mut buf).unwrap();
                        if n == 0 {
                            break;
                        }
                        stream.write_all(&buf[..n]).unwrap();
                    }
                }

                conn.send_close_notify(&mut output);
                complete_io(
                    &mut sock,
                    &mut input,
                    &mut received_plaintext,
                    &mut output,
                    &mut conn,
                )
                .unwrap();
            });
        }
    });

    client.enable_early_data = true;
    let client = Arc::new(client);
    let addr = SocketAddr::from(([127, 0, 0, 1], server_port));

    Ok((client, addr))
}

#[tokio::test]
async fn early_data_applies_output_backpressure() -> io::Result<()> {
    let (client, addr) = start_server(256 * 1024)?;
    let _ = send(client.clone(), addr, |stream| stream, b"prime", false).await?;

    let connector = TlsConnector::from(client).early_data(true);
    let domain = ServerName::try_from("foobar.com").unwrap();
    let mut stream = connector.connect(domain, ControlledIo::default()).await?;

    assert_eq!(stream.write(b"warmup").await?, 6);
    stream.get_mut().0.blocked = true;

    let data = vec![0u8; 128 * 1024];
    assert_eq!(stream.write(&data).await?, 64 * 1024);
    assert!(stream.write(&data[64 * 1024..]).now_or_never().is_none());

    Ok(())
}

#[derive(Debug, Default)]
struct ControlledIo {
    blocked: bool,
    written: usize,
}

impl AsyncRead for ControlledIo {
    fn poll_read(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        _: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Poll::Pending
    }
}

impl AsyncWrite for ControlledIo {
    fn poll_write(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if this.blocked {
            return Poll::Pending;
        }

        this.written += buf.len();
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.blocked {
            Poll::Pending
        } else {
            Poll::Ready(Ok(()))
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

// Include `utils` module
include!("utils.rs");
