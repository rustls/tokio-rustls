#![cfg(any(feature = "aws_lc_rs", feature = "ring"))]

use std::io::{self, Cursor};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use futures_util::future::poll_fn;
use futures_util::task::noop_waker_ref;
use rustls::pki_types::ServerName;
use rustls::{ClientConnection, Connection as _, ServerConnection, VecInput};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

use super::{CursorVec, Stream};

struct ConnectionState<C> {
    session: C,
    input: VecInput,
    tls: CursorVec,
    plaintext: CursorVec,
}

impl<C> ConnectionState<C> {
    fn new(session: C, tls: Vec<u8>) -> Self {
        Self {
            session,
            input: VecInput::default(),
            tls: CursorVec::from_vec(tls),
            plaintext: CursorVec::default(),
        }
    }
}

struct Good<'a>(&'a mut ConnectionState<ServerConnection>);

impl AsyncRead for Good<'_> {
    fn poll_read(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let n = buf.remaining().min(this.0.tls.len());
        if n == 0 {
            return Poll::Pending;
        }

        buf.put_slice(&this.0.tls.pending()[..n]);
        this.0.tls.consume(n);
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for Good<'_> {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let mut reader = buf;
        let len = this.0.input.read(&mut reader)?;
        this.0
            .session
            .process_new_packets(&mut this.0.input, this.0.tls.append_vec())
            .handle_all(this.0.plaintext.append_vec())
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
        Poll::Ready(Ok(len))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        this.0.session.send_close_notify(this.0.tls.append_vec());
        Poll::Ready(Ok(()))
    }
}

struct Pending;

impl AsyncRead for Pending {
    fn poll_read(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        _: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Poll::Pending
    }
}

impl AsyncWrite for Pending {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        _buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Poll::Pending
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

struct Expected(Cursor<Vec<u8>>);

impl AsyncRead for Expected {
    fn poll_read(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let n = std::io::Read::read(&mut this.0, buf.initialize_unfilled())?;
        buf.advance(n);

        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for Expected {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

struct Eof;

impl AsyncRead for Eof {
    fn poll_read(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        _buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for Eof {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        _buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Poll::Ready(Ok(0))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

#[tokio::test]
async fn stream_good() -> io::Result<()> {
    stream_good_impl(false, false).await
}

#[tokio::test]
async fn stream_good_vectored() -> io::Result<()> {
    stream_good_impl(true, false).await
}

#[tokio::test]
async fn stream_good_bufread() -> io::Result<()> {
    stream_good_impl(false, true).await
}

async fn stream_good_impl(vectored: bool, bufread: bool) -> io::Result<()> {
    const FILE: &[u8] = include_bytes!("../../README.md");

    let (mut server, mut client) = make_pair();
    poll_fn(|cx| do_handshake(&mut client, &mut server, cx)).await?;

    server
        .session
        .write_tls(FILE.into(), server.tls.append_vec())
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
    server.session.send_close_notify(server.tls.append_vec());

    {
        let mut good = Good(&mut server);
        let mut stream = Stream::new(
            &mut good,
            &mut client.session,
            &mut client.input,
            &mut client.tls,
            &mut client.plaintext,
        );

        let mut buf = Vec::new();
        if bufread {
            dbg!(tokio::io::copy_buf(&mut stream, &mut buf).await)?;
        } else {
            dbg!(stream.read_to_end(&mut buf).await)?;
        }
        assert_eq!(buf, FILE);

        dbg!(utils::write(&mut stream, b"Hello World!", vectored).await)?;
        stream.session.send_close_notify(stream.tls.append_vec());

        dbg!(stream.shutdown().await)?;
    }

    assert_eq!(server.plaintext.pending(), b"Hello World!");

    Ok(()) as io::Result<()>
}

#[tokio::test]
async fn stream_bad() -> io::Result<()> {
    let (mut server, mut client) = make_pair();
    poll_fn(|cx| do_handshake(&mut client, &mut server, cx)).await?;

    let mut bad = Pending;
    let mut stream = Stream::new(
        &mut bad,
        &mut client.session,
        &mut client.input,
        &mut client.tls,
        &mut client.plaintext,
    );
    assert_eq!(
        poll_fn(|cx| stream.as_mut_pin().poll_write(cx, &[0x42; 8])).await?,
        8
    );

    let mut cx = Context::from_waker(noop_waker_ref());
    let ret = stream.as_mut_pin().poll_write(&mut cx, &[0x01]);
    assert!(ret.is_pending());

    Ok(()) as io::Result<()>
}

#[tokio::test]
async fn stream_handshake() -> io::Result<()> {
    let (mut server, mut client) = make_pair();

    {
        let mut good = Good(&mut server);
        let mut stream = Stream::new(
            &mut good,
            &mut client.session,
            &mut client.input,
            &mut client.tls,
            &mut client.plaintext,
        );
        let (r, w) = poll_fn(|cx| stream.handshake(cx)).await?;

        assert!(r > 0);
        assert!(w > 0);

        poll_fn(|cx| stream.handshake(cx)).await?; // finish server handshake
    }

    assert!(!server.session.is_handshaking());
    assert!(!client.session.is_handshaking());

    Ok(()) as io::Result<()>
}

#[tokio::test]
async fn stream_buffered_handshake() -> io::Result<()> {
    use tokio::io::BufWriter;

    let (mut server, mut client) = make_pair();

    {
        let mut good = BufWriter::new(Good(&mut server));
        let mut stream = Stream::new(
            &mut good,
            &mut client.session,
            &mut client.input,
            &mut client.tls,
            &mut client.plaintext,
        );
        let (r, w) = poll_fn(|cx| stream.handshake(cx)).await?;

        assert!(r > 0);
        assert!(w > 0);

        poll_fn(|cx| stream.handshake(cx)).await?; // finish server handshake
    }

    assert!(!server.session.is_handshaking());
    assert!(!client.session.is_handshaking());

    Ok(()) as io::Result<()>
}

#[tokio::test]
async fn stream_handshake_eof() -> io::Result<()> {
    let (_, mut client) = make_pair();

    let mut bad = Expected(Cursor::new(Vec::new()));
    let mut stream = Stream::new(
        &mut bad,
        &mut client.session,
        &mut client.input,
        &mut client.tls,
        &mut client.plaintext,
    );

    let mut cx = Context::from_waker(noop_waker_ref());
    let r = stream.handshake(&mut cx);
    assert_eq!(
        r.map_err(|err| err.kind()),
        Poll::Ready(Err(io::ErrorKind::UnexpectedEof))
    );

    Ok(()) as io::Result<()>
}

#[tokio::test]
async fn stream_handshake_write_eof() -> io::Result<()> {
    let (_, mut client) = make_pair();

    let mut io = Eof;
    let mut stream = Stream::new(
        &mut io,
        &mut client.session,
        &mut client.input,
        &mut client.tls,
        &mut client.plaintext,
    );

    let mut cx = Context::from_waker(noop_waker_ref());
    let r = stream.handshake(&mut cx);
    assert_eq!(
        r.map_err(|err| err.kind()),
        Poll::Ready(Err(io::ErrorKind::WriteZero))
    );

    Ok(()) as io::Result<()>
}

// see https://github.com/tokio-rs/tls/issues/77
#[tokio::test]
async fn stream_handshake_regression_issues_77() -> io::Result<()> {
    let (_, mut client) = make_pair();

    let mut bad = Expected(Cursor::new(b"\x15\x03\x01\x00\x02\x02\x00".to_vec()));
    let mut stream = Stream::new(
        &mut bad,
        &mut client.session,
        &mut client.input,
        &mut client.tls,
        &mut client.plaintext,
    );

    let mut cx = Context::from_waker(noop_waker_ref());
    let r = stream.handshake(&mut cx);
    assert_eq!(
        r.map_err(|err| err.kind()),
        Poll::Ready(Err(io::ErrorKind::InvalidData))
    );

    Ok(()) as io::Result<()>
}

#[tokio::test]
async fn stream_eof() -> io::Result<()> {
    let (mut server, mut client) = make_pair();
    poll_fn(|cx| do_handshake(&mut client, &mut server, cx)).await?;

    let mut bad = Expected(Cursor::new(Vec::new()));
    let mut stream = Stream::new(
        &mut bad,
        &mut client.session,
        &mut client.input,
        &mut client.tls,
        &mut client.plaintext,
    );

    let mut buf = Vec::new();
    let result = stream.read_to_end(&mut buf).await;
    assert_eq!(
        result.err().map(|e| e.kind()),
        Some(io::ErrorKind::UnexpectedEof)
    );

    Ok(()) as io::Result<()>
}

#[tokio::test]
async fn stream_write_zero() -> io::Result<()> {
    let (mut server, mut client) = make_pair();
    poll_fn(|cx| do_handshake(&mut client, &mut server, cx)).await?;

    let mut io = Eof;
    let mut stream = Stream::new(
        &mut io,
        &mut client.session,
        &mut client.input,
        &mut client.tls,
        &mut client.plaintext,
    );

    stream.write_all(b"1").await.unwrap();
    let result = stream.flush().await;
    assert_eq!(
        result.err().map(|e| e.kind()),
        Some(io::ErrorKind::WriteZero)
    );

    Ok(()) as io::Result<()>
}

fn make_pair() -> (
    ConnectionState<ServerConnection>,
    ConnectionState<ClientConnection>,
) {
    let (sconfig, cconfig) = utils::make_configs();
    let server = ServerConnection::new(Arc::new(sconfig)).unwrap();

    let domain = ServerName::try_from("foobar.com").unwrap().to_owned();
    let mut client_tls = Vec::new();
    let client = Arc::new(cconfig)
        .connect(domain)
        .build(&mut client_tls)
        .unwrap();

    (
        ConnectionState::new(server, Vec::new()),
        ConnectionState::new(client, client_tls),
    )
}

fn do_handshake(
    client: &mut ConnectionState<ClientConnection>,
    server: &mut ConnectionState<ServerConnection>,
    cx: &mut Context<'_>,
) -> Poll<io::Result<()>> {
    let mut good = Good(server);
    let mut stream = Stream::new(
        &mut good,
        &mut client.session,
        &mut client.input,
        &mut client.tls,
        &mut client.plaintext,
    );

    while stream.session.is_handshaking() {
        ready!(stream.handshake(cx))?;
    }

    while !stream.tls.is_empty() {
        ready!(stream.write_io(cx))?;
    }

    Poll::Ready(Ok(()))
}

// Share `utils` module with integration tests
include!("../../tests/utils.rs");
