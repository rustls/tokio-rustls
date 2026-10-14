use std::io::{self, Cursor};
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::channel;
use std::sync::{Arc, LazyLock};
use std::task::{Context, Poll};
use std::{future, thread};

use futures_util::future::TryFutureExt;
use rcgen::CertifiedKey;
use rustls_aws_lc_rs::DEFAULT_PROVIDER;
use tokio::io::{
    AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _, DuplexStream, ReadBuf, copy,
    split,
};
use tokio::net::{TcpListener, TcpStream};
use tokio::runtime;
use tokio_rustls::rustls::crypto::{Credentials, Identity, SingleCredential};
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use tokio_rustls::rustls::{ClientConfig, RootCertStore, ServerConfig};
use tokio_rustls::{TlsAcceptor, TlsConnector, TlsStreamParts};

#[expect(clippy::incompatible_msrv)]
static TEST_SERVER: LazyLock<SocketAddr> = LazyLock::new(|| {
    let (config, _) = utils::make_configs();
    let acceptor = TlsAcceptor::from(Arc::new(config));

    let (send, recv) = channel();

    thread::spawn(move || {
        let runtime = runtime::Builder::new_current_thread()
            .enable_io()
            .build()
            .unwrap();
        let runtime = Arc::new(runtime);
        let runtime2 = runtime.clone();

        let done = async move {
            let addr = SocketAddr::from(([127, 0, 0, 1], 0));
            let listener = TcpListener::bind(&addr).await?;

            send.send(listener.local_addr()?).unwrap();

            loop {
                let (stream, _) = listener.accept().await?;

                let acceptor = acceptor.clone();
                let fut = async move {
                    let stream = acceptor.accept(stream).await?;

                    let (mut reader, mut writer) = split(stream);
                    copy(&mut reader, &mut writer).await?;

                    Ok(()) as io::Result<()>
                }
                .unwrap_or_else(|err| eprintln!("server: {:?}", err));

                runtime2.spawn(fut);
            }
        }
        .unwrap_or_else(|err: io::Error| eprintln!("server: {:?}", err));

        runtime.block_on(done);
    });

    recv.recv().unwrap()
});

async fn start_client<S: AsyncRead + AsyncWrite + Unpin>(
    addr: SocketAddr,
    domain: &str,
    config: Arc<ClientConfig>,
    wrapper: impl FnOnce(TcpStream) -> S,
    use_buf_read: bool,
) -> io::Result<()> {
    const FILE: &[u8] = include_bytes!("../README.md");

    let domain = ServerName::try_from(domain).unwrap().to_owned();
    let config = TlsConnector::from(config);
    let mut buf = vec![0; FILE.len()];

    let stream = wrapper(TcpStream::connect(&addr).await?);
    let mut stream = config.connect(domain, stream).await?;
    stream.write_all(FILE).await?;
    stream.flush().await?;
    if use_buf_read {
        tokio::io::copy_buf(
            &mut (&mut stream).take(FILE.len() as u64),
            &mut Cursor::new(&mut buf),
        )
        .await?;
    } else {
        stream.read_exact(&mut buf).await?;
    }

    assert_eq!(buf, FILE);

    Ok(())
}

async fn pass_impl<S: AsyncRead + AsyncWrite + Unpin>(
    wrapper: impl FnOnce(TcpStream) -> S,
    use_buf_read: bool,
) -> io::Result<()> {
    // TODO: not sure how to resolve this right now but since
    // TcpStream::bind now returns a future it creates a race
    // condition until its ready sometimes.
    use std::time::*;
    tokio::time::sleep(Duration::from_secs(1)).await;

    let (_, config) = utils::make_configs();
    let config = Arc::new(config);

    start_client(
        *TEST_SERVER,
        utils::TEST_SERVER_DOMAIN,
        config,
        wrapper,
        use_buf_read,
    )
    .await?;

    Ok(())
}

#[tokio::test]
async fn pass() -> io::Result<()> {
    pass_impl(|stream| stream, false).await
}

#[tokio::test]
async fn pass_buf_read() -> io::Result<()> {
    pass_impl(|stream| stream, true).await
}

#[tokio::test]
async fn fail() -> io::Result<()> {
    let (_, config) = utils::make_configs();
    let config = Arc::new(config);

    assert_ne!(utils::TEST_SERVER_DOMAIN, "google.com");
    let ret = start_client(*TEST_SERVER, "google.com", config, |stream| stream, false).await;
    assert!(ret.is_err());

    Ok(())
}

// Regression test for https://github.com/rustls/tokio-rustls/issues/204
#[tokio::test]
async fn propagate_connection_aborted() {
    const HOST: &str = "localhost";
    const PAYLOAD: &[u8] = b"hello";

    /// Reports `ConnectionAborted` instead of parking, once armed. Buffered bytes
    /// are delivered first, so the abort occurs strictly after the payload.
    struct ImitateConnectionAbortedAfterPayload<'a> {
        delegate: DuplexStream,
        trigger_connection_aborted: &'a AtomicBool,
    }

    impl AsyncRead for ImitateConnectionAbortedAfterPayload<'_> {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            match Pin::new(&mut self.delegate).poll_read(cx, buf) {
                Poll::Pending if self.trigger_connection_aborted.load(Ordering::SeqCst) => {
                    Poll::Ready(Err(io::Error::from(io::ErrorKind::ConnectionAborted)))
                }
                other => other,
            }
        }
    }

    impl AsyncWrite for ImitateConnectionAbortedAfterPayload<'_> {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            Pin::new(&mut self.delegate).poll_write(cx, buf)
        }

        fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.delegate).poll_flush(cx)
        }

        fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.delegate).poll_shutdown(cx)
        }
    }

    let CertifiedKey { cert, signing_key } =
        rcgen::generate_simple_self_signed([HOST.to_owned()]).unwrap();
    let cert = CertificateDer::from(cert);
    let signing_key = PrivateKeyDer::from(signing_key);

    let provider = Arc::new(DEFAULT_PROVIDER);
    let server_config = ServerConfig::builder(provider.clone())
        .with_no_client_auth()
        .with_server_credential_resolver(Arc::new(SingleCredential::from(
            Credentials::from_der(
                Arc::new(Identity::from_cert_chain(vec![cert.clone()]).unwrap()),
                signing_key,
                &provider,
            )
            .unwrap(),
        )))
        .unwrap();

    let client_config = ClientConfig::builder(provider)
        .with_root_certificates({
            let mut roots = RootCertStore::empty();
            roots.add(cert).unwrap();
            roots
        })
        .with_no_client_auth()
        .unwrap();

    let (client_io, server_io) = tokio::io::duplex(16 * 1024);
    let trigger_connection_aborted = AtomicBool::new(false);
    let (set_payload_written, wait_for_payload_written) = tokio::sync::oneshot::channel();

    let server = tokio::spawn(async move {
        let mut tls = TlsAcceptor::from(Arc::new(server_config))
            .accept(server_io)
            .await
            .unwrap();
        tls.write_all(PAYLOAD).await.unwrap();
        tls.flush().await.unwrap();
        set_payload_written.send(()).unwrap();
        future::pending::<()>().await;
    });

    let mut tls = TlsConnector::from(Arc::new(client_config))
        .connect(
            ServerName::try_from(HOST).unwrap(),
            ImitateConnectionAbortedAfterPayload {
                delegate: client_io,
                trigger_connection_aborted: &trigger_connection_aborted,
            },
        )
        .await
        .unwrap();

    // Arm before the first read so the abort lands inside a single `poll_read`:
    // the payload record is already buffered and satisfies the first fill, then
    // the read buffer still has room, so a second fill meets the dead transport.
    wait_for_payload_written.await.unwrap();
    trigger_connection_aborted.store(true, Ordering::SeqCst);

    let mut buf = [0u8; 1024];
    let n = tls.read(&mut buf).await.unwrap();
    assert_eq!(&buf[..n], PAYLOAD);

    let error = tls.read(&mut buf).await.expect_err(
        "a ConnectionAborted transport error must surface, not be swallowed into a clean EOF",
    );
    assert_eq!(
        error.kind(),
        io::ErrorKind::ConnectionAborted,
        "the original transport error kind should be preserved"
    );

    server.abort();
}

// Include `utils` module
include!("utils.rs");

#[tokio::test]
async fn from_parts_roundtrip() -> io::Result<()> {
    let (sconfig, cconfig) = utils::make_configs();
    let (cstream, sstream) = tokio::io::duplex(1200);
    let domain = ServerName::try_from(utils::TEST_SERVER_DOMAIN)
        .unwrap()
        .to_owned();

    let client = tokio::spawn(async move {
        let connector = TlsConnector::from(Arc::new(cconfig));
        let mut client = connector.connect(domain, cstream).await?;
        client.write_all(b"hello, world!").await?;
        client.flush().await?;

        let parts = client.into_inner();
        let mut client = tokio_rustls::client::TlsStream::from_parts(parts);

        let mut buf = [0; 3];
        client.read_exact(&mut buf).await?;
        assert_eq!(&buf, b"bye");
        client.shutdown().await?;
        assert_eq!(client.read(&mut buf).await?, 0);
        Ok::<_, io::Error>(())
    });

    let acceptor = TlsAcceptor::from(Arc::new(sconfig));
    let mut server = acceptor.accept(sstream).await?;

    // Consume only part of the record so the rest stays buffered in the session.
    let mut buf = [0; 5];
    server.read_exact(&mut buf).await?;
    assert_eq!(&buf, b"hello");

    let parts = server.into_inner();
    let mut server = tokio_rustls::server::TlsStream::from_parts(parts);

    let mut buf = [0; 8];
    server.read_exact(&mut buf).await?;
    assert_eq!(&buf, b", world!");

    server.write_all(b"bye").await?;
    server.flush().await?;
    assert_eq!(server.read(&mut buf).await?, 0);
    server.shutdown().await?;

    client.await.unwrap()
}

// Move an established server-side stream to a runtime on another thread.
#[tokio::test]
async fn from_parts_across_runtimes() -> io::Result<()> {
    let (sconfig, cconfig) = utils::make_configs();
    let listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0))).await?;
    let addr = listener.local_addr()?;

    let server = tokio::spawn(async move {
        let acceptor = TlsAcceptor::from(Arc::new(sconfig));
        let (stream, _) = listener.accept().await?;
        let stream = acceptor.accept(stream).await?;

        // Detach the socket from this runtime and hand the established
        // connection to a runtime on another thread, which re-registers it.
        let TlsStreamParts {
            io,
            conn,
            input,
            tls,
            received_plaintext,
        } = stream.into_inner();
        let io = io.into_std()?;
        let worker = thread::spawn(move || {
            runtime::Builder::new_current_thread()
                .enable_io()
                .build()?
                .block_on(async move {
                    let mut stream = tokio_rustls::server::TlsStream::from_parts(TlsStreamParts {
                        io: TcpStream::from_std(io)?,
                        conn,
                        input,
                        tls,
                        received_plaintext,
                    });

                    let mut buf = [0; 4];
                    stream.read_exact(&mut buf).await?;
                    assert_eq!(&buf, b"ping");
                    stream.write_all(b"pong").await?;
                    stream.flush().await?;
                    assert_eq!(stream.read(&mut buf).await?, 0);
                    stream.shutdown().await
                })
        });
        tokio::task::spawn_blocking(move || worker.join().unwrap())
            .await
            .unwrap()
    });

    let domain = ServerName::try_from(utils::TEST_SERVER_DOMAIN)
        .unwrap()
        .to_owned();
    let connector = TlsConnector::from(Arc::new(cconfig));
    let stream = TcpStream::connect(addr).await?;
    let mut client = connector.connect(domain, stream).await?;
    client.write_all(b"ping").await?;
    client.flush().await?;

    let mut buf = [0; 4];
    client.read_exact(&mut buf).await?;
    assert_eq!(&buf, b"pong");
    client.shutdown().await?;
    assert_eq!(client.read(&mut buf).await?, 0);

    server.await.unwrap()
}
