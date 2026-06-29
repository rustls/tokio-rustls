use std::future::Future;
use std::io::{self, BufRead as _};
#[cfg(unix)]
use std::os::unix::io::{AsRawFd, RawFd};
#[cfg(windows)]
use std::os::windows::io::{AsRawSocket, RawSocket};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use rustls::server::AcceptedAlert;
use rustls::{ServerConfig, ServerConnection};
use tokio::io::{AsyncBufRead, AsyncRead, AsyncWrite, ReadBuf};
use tokio::time::Instant;

use crate::common::{
    HandshakeFuture, IoSession, MidHandshake, Stream, SyncReadAdapter, SyncWriteAdapter, Timeout,
    TlsState,
};

/// A wrapper around a `rustls::ServerConfig`, providing an async `accept` method.
#[derive(Clone)]
pub struct TlsAcceptor {
    inner: Arc<ServerConfig>,
    handshake_timeout: Option<Duration>,
}

impl From<Arc<ServerConfig>> for TlsAcceptor {
    fn from(inner: Arc<ServerConfig>) -> Self {
        Self {
            inner,
            handshake_timeout: None,
        }
    }
}

impl TlsAcceptor {
    /// Set the maximum amount of time to allow for TLS handshakes.
    ///
    /// `None` disables the handshake timeout.
    ///
    /// The timeout applies to handshakes started via [`TlsAcceptor::accept`] and
    /// [`TlsAcceptor::accept_with`]. For the lazy-acceptor flow, set the timeout
    /// on the [`LazyConfigAcceptor`] itself via
    /// [`LazyConfigAcceptor::with_handshake_timeout`]. The deadline established
    /// there is inherited by the [`Accept`] returned from
    /// [`StartHandshake::into_stream`], so a single timeout covers both phases.
    pub fn with_handshake_timeout(mut self, timeout: Option<Duration>) -> Self {
        self.handshake_timeout = timeout;
        self
    }

    #[inline]
    pub fn accept<IO>(&self, stream: IO) -> Accept<IO>
    where
        IO: AsyncRead + AsyncWrite + Unpin,
    {
        self.accept_with(stream, |_| ())
    }

    pub fn accept_with<IO, F>(&self, stream: IO, f: F) -> Accept<IO>
    where
        IO: AsyncRead + AsyncWrite + Unpin,
        F: FnOnce(&mut ServerConnection),
    {
        let mut session = match ServerConnection::new(self.inner.clone()) {
            Ok(session) => session,
            Err(error) => {
                return Accept(HandshakeFuture::new(
                    MidHandshake::Error {
                        io: stream,
                        // TODO(eliza): should this really return an `io::Error`?
                        // Probably not...
                        error: io::Error::new(io::ErrorKind::Other, error),
                    },
                    self.handshake_timeout,
                ));
            }
        };
        f(&mut session);

        Accept(HandshakeFuture::new(
            MidHandshake::Handshaking(TlsStream {
                session,
                io: stream,
                state: TlsState::Stream,
                need_flush: false,
            }),
            self.handshake_timeout,
        ))
    }

    /// Get a read-only reference to underlying config
    pub fn config(&self) -> &Arc<ServerConfig> {
        &self.inner
    }
}

pub struct LazyConfigAcceptor<IO> {
    acceptor: rustls::server::Acceptor,
    io: Option<IO>,
    alert: Option<(rustls::Error, AcceptedAlert)>,
    timeout: Option<Timeout>,
}

impl<IO> LazyConfigAcceptor<IO>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    #[inline]
    pub fn new(acceptor: rustls::server::Acceptor, io: IO) -> Self {
        Self {
            acceptor,
            io: Some(io),
            alert: None,
            timeout: None,
        }
    }

    /// Set the maximum amount of time to allow for the TLS handshake.
    ///
    /// `None` disables the handshake timeout.
    ///
    /// The deadline is fixed to `Instant::now() + duration` when this builder
    /// is called and spans both phases of the lazy-acceptor flow:
    ///
    /// 1. The ClientHello phase driven by this `LazyConfigAcceptor`.
    /// 2. The post-ClientHello phase driven by the [`Accept`] returned from
    ///    [`StartHandshake::into_stream`].
    ///
    /// Both phases race against the same wall-clock deadline, so a single
    /// timeout covers the full handshake. To set a timeout on handshakes
    /// driven via [`TlsAcceptor::accept`] instead, use
    /// [`TlsAcceptor::with_handshake_timeout`].
    pub fn with_handshake_timeout(mut self, timeout: Option<Duration>) -> Self {
        self.timeout = timeout.map(Timeout::from_duration);
        self
    }

    /// Takes back the client connection. Will return `None` if called more than once or if the
    /// connection has been accepted.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # fn choose_server_config(
    /// #     _: rustls::server::ClientHello,
    /// # ) -> std::sync::Arc<rustls::ServerConfig> {
    /// #     unimplemented!();
    /// # }
    /// # #[allow(unused_variables)]
    /// # async fn listen() {
    /// use tokio::io::AsyncWriteExt;
    /// let listener = tokio::net::TcpListener::bind("127.0.0.1:4443").await.unwrap();
    /// let (stream, _) = listener.accept().await.unwrap();
    ///
    /// let acceptor = tokio_rustls::LazyConfigAcceptor::new(rustls::server::Acceptor::default(), stream);
    /// tokio::pin!(acceptor);
    ///
    /// match acceptor.as_mut().await {
    ///     Ok(start) => {
    ///         let clientHello = start.client_hello();
    ///         let config = choose_server_config(clientHello);
    ///         let stream = start.into_stream(config).await.unwrap();
    ///         // Proceed with handling the ServerConnection...
    ///     }
    ///     Err(err) => {
    ///         if let Some(mut stream) = acceptor.take_io() {
    ///             stream
    ///                 .write_all(
    ///                     format!("HTTP/1.1 400 Invalid Input\r\n\r\n\r\n{:?}\n", err)
    ///                         .as_bytes()
    ///                 )
    ///                 .await
    ///                 .unwrap();
    ///         }
    ///     }
    /// }
    /// # }
    /// ```
    pub fn take_io(&mut self) -> Option<IO> {
        self.io.take()
    }
}

impl<IO> Future for LazyConfigAcceptor<IO>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    type Output = Result<StartHandshake<IO>, io::Error>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        loop {
            let io = match this.io.as_mut() {
                Some(io) => io,
                None => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::Other,
                        "acceptor cannot be polled after acceptance",
                    )));
                }
            };

            if let Some((err, mut alert)) = this.alert.take() {
                match alert.write(&mut SyncWriteAdapter { io, cx }) {
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                        this.alert = Some((err, alert));
                        return poll_pending_or_timeout(&mut this.timeout, cx);
                    }
                    Ok(0) | Err(_) => {
                        return Poll::Ready(Err(io::Error::new(io::ErrorKind::InvalidData, err)));
                    }
                    Ok(_) => {
                        this.alert = Some((err, alert));
                        continue;
                    }
                };
            }

            let mut reader = SyncReadAdapter { io, cx };
            match this.acceptor.read_tls(&mut reader) {
                Ok(0) => return Err(io::ErrorKind::UnexpectedEof.into()).into(),
                Ok(_) => {}
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    return poll_pending_or_timeout(&mut this.timeout, cx);
                }
                Err(e) => return Err(e).into(),
            }

            match this.acceptor.accept() {
                Ok(Some(accepted)) => {
                    let io = this.io.take().unwrap();
                    return Poll::Ready(Ok(StartHandshake {
                        accepted,
                        io,
                        deadline: this.timeout.as_ref().map(Timeout::deadline),
                    }));
                }
                Ok(None) => {}
                Err((err, alert)) => {
                    this.alert = Some((err, alert));
                }
            }
        }
    }
}

/// Returns `Poll::Pending`, unless the timeout has elapsed, in which case a `TimedOut`
/// error is returned. With no timeout configured, always returns `Poll::Pending`.
fn poll_pending_or_timeout<T>(
    timeout: &mut Option<Timeout>,
    cx: &mut Context<'_>,
) -> Poll<Result<T, io::Error>> {
    let timeout = match timeout {
        Some(timeout) => timeout,
        None => return Poll::Pending,
    };
    if timeout.poll_deadline(cx).is_pending() {
        return Poll::Pending;
    }
    Poll::Ready(Err(io::Error::new(
        io::ErrorKind::TimedOut,
        "TLS handshake timed out",
    )))
}

/// An incoming connection received through [`LazyConfigAcceptor`].
///
/// This contains the generic `IO` asynchronous transport,
/// [`ClientHello`](rustls::server::ClientHello) data,
/// and all the state required to continue the TLS handshake (e.g. via
/// [`StartHandshake::into_stream`]).
#[non_exhaustive]
#[derive(Debug)]
pub struct StartHandshake<IO> {
    pub accepted: rustls::server::Accepted,
    pub io: IO,
    // Handshake deadline inherited from the LazyConfigAcceptor, if any.
    // Propagated into the Accept returned by into_stream so the timeout
    // spans both phases of the handshake.
    pub(crate) deadline: Option<Instant>,
}

impl<IO> StartHandshake<IO>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    /// Create a new object from an `IO` transport and prior TLS metadata.
    pub fn from_parts(accepted: rustls::server::Accepted, transport: IO) -> Self {
        Self {
            accepted,
            io: transport,
            deadline: None,
        }
    }

    pub fn client_hello(&self) -> rustls::server::ClientHello<'_> {
        self.accepted.client_hello()
    }

    pub fn into_stream(self, config: Arc<ServerConfig>) -> Accept<IO> {
        self.into_stream_with(config, |_| ())
    }

    pub fn into_stream_with<F>(self, config: Arc<ServerConfig>, f: F) -> Accept<IO>
    where
        F: FnOnce(&mut ServerConnection),
    {
        let mut conn = match self.accepted.into_connection(config) {
            Ok(conn) => conn,
            Err((error, alert)) => {
                return Accept(HandshakeFuture::from_deadline(
                    MidHandshake::SendAlert {
                        io: self.io,
                        alert,
                        // TODO(eliza): should this really return an `io::Error`?
                        // Probably not...
                        error: io::Error::new(io::ErrorKind::InvalidData, error),
                    },
                    self.deadline,
                ));
            }
        };
        f(&mut conn);

        Accept(HandshakeFuture::from_deadline(
            MidHandshake::Handshaking(TlsStream {
                session: conn,
                io: self.io,
                state: TlsState::Stream,
                need_flush: false,
            }),
            self.deadline,
        ))
    }
}

/// Future returned from `TlsAcceptor::accept` which will resolve
/// once the accept handshake has finished.
pub struct Accept<IO>(HandshakeFuture<TlsStream<IO>>);

impl<IO> Accept<IO> {
    #[inline]
    pub fn into_fallible(self) -> FallibleAccept<IO> {
        FallibleAccept(self.0)
    }

    pub fn get_ref(&self) -> Option<&IO> {
        match self.0.handshake() {
            MidHandshake::Handshaking(sess) => Some(sess.get_ref().0),
            MidHandshake::SendAlert { io, .. } => Some(io),
            MidHandshake::Error { io, .. } => Some(io),
            MidHandshake::End => None,
        }
    }

    pub fn get_mut(&mut self) -> Option<&mut IO> {
        match self.0.handshake_mut() {
            MidHandshake::Handshaking(sess) => Some(sess.get_mut().0),
            MidHandshake::SendAlert { io, .. } => Some(io),
            MidHandshake::Error { io, .. } => Some(io),
            MidHandshake::End => None,
        }
    }
}

impl<IO: AsyncRead + AsyncWrite + Unpin> Future for Accept<IO> {
    type Output = io::Result<TlsStream<IO>>;

    #[inline]
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.get_mut().0.poll(cx).map_err(|(err, _)| err)
    }
}

/// Like [Accept], but returns `IO` on failure.
pub struct FallibleAccept<IO>(HandshakeFuture<TlsStream<IO>>);

impl<IO: AsyncRead + AsyncWrite + Unpin> Future for FallibleAccept<IO> {
    type Output = Result<TlsStream<IO>, (io::Error, IO)>;

    #[inline]
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.get_mut().0.poll(cx)
    }
}

/// A wrapper around an underlying raw stream which implements the TLS or SSL
/// protocol.
#[derive(Debug)]
pub struct TlsStream<IO> {
    pub(crate) io: IO,
    pub(crate) session: ServerConnection,
    pub(crate) state: TlsState,
    pub(crate) need_flush: bool,
}

impl<IO> TlsStream<IO> {
    #[inline]
    pub fn get_ref(&self) -> (&IO, &ServerConnection) {
        (&self.io, &self.session)
    }

    #[inline]
    pub fn get_mut(&mut self) -> (&mut IO, &mut ServerConnection) {
        (&mut self.io, &mut self.session)
    }

    #[inline]
    pub fn into_inner(self) -> (IO, ServerConnection) {
        (self.io, self.session)
    }
}

impl<IO> IoSession for TlsStream<IO> {
    type Io = IO;
    type Session = ServerConnection;

    #[inline]
    fn skip_handshake(&self) -> bool {
        false
    }

    #[inline]
    fn get_mut(&mut self) -> (&mut TlsState, &mut Self::Io, &mut Self::Session, &mut bool) {
        (
            &mut self.state,
            &mut self.io,
            &mut self.session,
            &mut self.need_flush,
        )
    }

    #[inline]
    fn into_io(self) -> Self::Io {
        self.io
    }
}

impl<IO> AsyncRead for TlsStream<IO>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let data = ready!(self.as_mut().poll_fill_buf(cx))?;
        let len = data.len().min(buf.remaining());
        buf.put_slice(&data[..len]);
        self.consume(len);
        Poll::Ready(Ok(()))
    }
}

impl<IO> AsyncBufRead for TlsStream<IO>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_fill_buf(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<&[u8]>> {
        match self.state {
            TlsState::Stream | TlsState::WriteShutdown => {
                let this = self.get_mut();
                let stream =
                    Stream::new(&mut this.io, &mut this.session).set_eof(!this.state.readable());

                match stream.poll_fill_buf(cx) {
                    Poll::Ready(Ok(buf)) => {
                        if buf.is_empty() {
                            this.state.shutdown_read();
                        }

                        Poll::Ready(Ok(buf))
                    }
                    Poll::Ready(Err(err)) if err.kind() == io::ErrorKind::ConnectionAborted => {
                        this.state.shutdown_read();
                        Poll::Ready(Err(err))
                    }
                    output => output,
                }
            }
            TlsState::ReadShutdown | TlsState::FullyShutdown => Poll::Ready(Ok(&[])),
            #[cfg(feature = "early-data")]
            ref s => unreachable!("server TLS can not hit this state: {:?}", s),
        }
    }

    fn consume(mut self: Pin<&mut Self>, amt: usize) {
        self.session.reader().consume(amt);
    }
}

impl<IO> AsyncWrite for TlsStream<IO>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    /// Note: that it does not guarantee the final data to be sent.
    /// To be cautious, you must manually call `flush`.
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let mut stream =
            Stream::new(&mut this.io, &mut this.session).set_eof(!this.state.readable());
        stream.as_mut_pin().poll_write(cx, buf)
    }

    /// Note: that it does not guarantee the final data to be sent.
    /// To be cautious, you must manually call `flush`.
    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let mut stream =
            Stream::new(&mut this.io, &mut this.session).set_eof(!this.state.readable());
        stream.as_mut_pin().poll_write_vectored(cx, bufs)
    }

    #[inline]
    fn is_write_vectored(&self) -> bool {
        true
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let mut stream =
            Stream::new(&mut this.io, &mut this.session).set_eof(!this.state.readable());
        stream.as_mut_pin().poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.state.writeable() {
            self.session.send_close_notify();
            self.state.shutdown_write();
        }

        let this = self.get_mut();
        let mut stream =
            Stream::new(&mut this.io, &mut this.session).set_eof(!this.state.readable());
        stream.as_mut_pin().poll_shutdown(cx)
    }
}

#[cfg(unix)]
impl<IO> AsRawFd for TlsStream<IO>
where
    IO: AsRawFd,
{
    fn as_raw_fd(&self) -> RawFd {
        self.get_ref().0.as_raw_fd()
    }
}

#[cfg(windows)]
impl<IO> AsRawSocket for TlsStream<IO>
where
    IO: AsRawSocket,
{
    fn as_raw_socket(&self) -> RawSocket {
        self.get_ref().0.as_raw_socket()
    }
}
