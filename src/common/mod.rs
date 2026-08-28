use std::io::{self, IoSlice, Read, Write};
use std::pin::Pin;
use std::task::{Context, Poll};

use rustls::crypto::cipher::OutboundPlain;
use rustls::{Connection as RustlsConnection, VecInput};
use tokio::io::{AsyncBufRead, AsyncRead, AsyncWrite, ReadBuf};

pub(crate) const DEFAULT_BUFFER_LIMIT: usize = 64 * 1024;

mod handshake;
pub(crate) use handshake::{IoSession, IoSessionParts, MidHandshake};

/// A `Vec<u8>` with an advancing read cursor.
///
/// Rustls appends output to a `Vec<u8>`, while Tokio may consume that output a
/// little at a time. Keeping a cursor avoids shifting the remaining bytes on
/// every partial read or write.
#[derive(Default)]
pub(crate) struct CursorVec {
    bytes: Vec<u8>,
    start: usize,
}

impl std::fmt::Debug for CursorVec {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(self.pending(), f)
    }
}

impl CursorVec {
    pub(crate) fn from_vec(bytes: Vec<u8>) -> Self {
        Self { bytes, start: 0 }
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub(crate) fn len(&self) -> usize {
        self.bytes.len() - self.start
    }

    pub(crate) fn pending(&self) -> &[u8] {
        &self.bytes[self.start..]
    }

    pub(crate) fn consume(&mut self, amount: usize) {
        assert!(amount <= self.len());
        self.start += amount;

        if self.start == self.bytes.len() {
            self.bytes.clear();
            self.start = 0;
        }
    }

    pub(crate) fn clear(&mut self) {
        self.bytes.clear();
        self.start = 0;
    }

    /// Returns the backing vector for APIs that only append to it.
    ///
    /// The vector may still contain a consumed prefix, so callers must not
    /// inspect or replace its existing contents.
    ///
    /// Compact only after at least half the stored bytes have been consumed.
    /// This bounds the retained prefix across appends while making compaction
    /// amortized linear.
    pub(crate) fn append_vec(&mut self) -> &mut Vec<u8> {
        let remaining = self.len();
        if remaining == 0 {
            self.clear();
        } else if self.start >= remaining {
            self.bytes.copy_within(self.start.., 0);
            self.bytes.truncate(remaining);
            self.start = 0;
        }

        &mut self.bytes
    }

    #[cfg(test)]
    fn into_pending_vec(mut self) -> Vec<u8> {
        let remaining = self.len();
        if self.start != 0 {
            self.bytes.copy_within(self.start.., 0);
            self.bytes.truncate(remaining);
        }
        self.bytes
    }
}

#[derive(Debug)]
pub(crate) enum TlsState {
    #[cfg(feature = "early-data")]
    EarlyData(usize, Vec<u8>),
    Stream,
    ReadShutdown,
    WriteShutdown,
    FullyShutdown,
}

impl TlsState {
    #[inline]
    pub(crate) fn shutdown_read(&mut self) {
        match *self {
            Self::WriteShutdown | Self::FullyShutdown => *self = Self::FullyShutdown,
            _ => *self = Self::ReadShutdown,
        }
    }

    #[inline]
    pub(crate) fn shutdown_write(&mut self) {
        match *self {
            Self::ReadShutdown | Self::FullyShutdown => *self = Self::FullyShutdown,
            _ => *self = Self::WriteShutdown,
        }
    }

    #[inline]
    pub(crate) fn writeable(&self) -> bool {
        !matches!(*self, Self::WriteShutdown | Self::FullyShutdown)
    }

    #[inline]
    pub(crate) fn readable(&self) -> bool {
        !matches!(*self, Self::ReadShutdown | Self::FullyShutdown)
    }

    #[inline]
    #[cfg(feature = "early-data")]
    pub(crate) fn is_early_data(&self) -> bool {
        matches!(self, Self::EarlyData(..))
    }

    #[inline]
    #[cfg(not(feature = "early-data"))]
    pub(crate) const fn is_early_data(&self) -> bool {
        false
    }
}

pub(crate) struct Stream<'a, IO, C> {
    pub(crate) io: &'a mut IO,
    pub(crate) session: &'a mut C,
    pub(crate) input: &'a mut VecInput,
    pub(crate) tls: &'a mut CursorVec,
    pub(crate) plaintext: &'a mut CursorVec,
    pub(crate) eof: bool,
    pub(crate) need_flush: bool,
}

impl<'a, IO: AsyncRead + AsyncWrite + Unpin, C> Stream<'a, IO, C>
where
    C: RustlsConnection,
{
    pub(crate) fn new(
        io: &'a mut IO,
        session: &'a mut C,
        input: &'a mut VecInput,
        tls: &'a mut CursorVec,
        plaintext: &'a mut CursorVec,
    ) -> Self {
        Stream {
            io,
            session,
            input,
            tls,
            plaintext,
            // The state so far is only used to detect EOF, so both Stream
            // and EarlyData states should be acceptable.
            eof: false,
            // Whether a previous flush returned pending, or a write occured without a flush.
            need_flush: false,
        }
    }

    pub(crate) fn set_eof(mut self, eof: bool) -> Self {
        self.eof = eof;
        self
    }

    pub(crate) fn set_need_flush(mut self, need_flush: bool) -> Self {
        self.need_flush = need_flush;
        self
    }

    pub(crate) fn as_mut_pin(&mut self) -> Pin<&mut Self> {
        Pin::new(self)
    }

    pub(crate) fn read_io(&mut self, cx: &mut Context) -> Poll<io::Result<usize>> {
        let mut reader = SyncReadAdapter { io: self.io, cx };

        let n = match self.input.read(&mut reader) {
            Ok(n) => n,
            Err(ref err) if err.kind() == io::ErrorKind::WouldBlock => return Poll::Pending,
            Err(err) => return Poll::Ready(Err(err)),
        };

        let processed = self
            .session
            .process_new_packets(self.input, self.tls.append_vec())
            .handle_all(self.plaintext.append_vec());

        if let Err(err) = processed {
            // In case we have an alert to send describing this error,
            // try a last-gasp write -- but don't predate the primary
            // error.
            let _ = self.write_io(cx);

            return Poll::Ready(Err(io::Error::new(io::ErrorKind::InvalidData, err)));
        }

        Poll::Ready(Ok(n))
    }

    pub(crate) fn write_io(&mut self, cx: &mut Context) -> Poll<io::Result<usize>> {
        if self.tls.is_empty() {
            return Poll::Ready(Ok(0));
        }

        let available = self.tls.len();
        match Pin::new(&mut self.io).poll_write(cx, self.tls.pending()) {
            Poll::Ready(Ok(n)) if n > available => {
                // The amount actually written is unknowable after a broken
                // AsyncWrite implementation violates its contract.
                self.tls.clear();
                Poll::Ready(Err(io::Error::other(format!(
                    "illegal poll_write() return value ({n} > {available})"
                ))))
            }
            Poll::Ready(Ok(n)) => {
                self.tls.consume(n);
                self.need_flush |= n != 0;
                Poll::Ready(Ok(n))
            }
            Poll::Ready(Err(err)) => Poll::Ready(Err(err)),
            Poll::Pending => Poll::Pending,
        }
    }

    pub(crate) fn handshake(&mut self, cx: &mut Context) -> Poll<io::Result<(usize, usize)>> {
        let mut wrlen = 0;
        let mut rdlen = 0;

        loop {
            let mut write_would_block = false;
            let mut read_would_block = false;

            while !self.tls.is_empty() {
                match self.write_io(cx) {
                    Poll::Ready(Ok(0)) => return Poll::Ready(Err(io::ErrorKind::WriteZero.into())),
                    Poll::Ready(Ok(n)) => {
                        wrlen += n;
                        self.need_flush = true;
                    }
                    Poll::Pending => {
                        write_would_block = true;
                        break;
                    }
                    Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                }
            }

            if self.need_flush {
                match Pin::new(&mut self.io).poll_flush(cx) {
                    Poll::Ready(Ok(())) => self.need_flush = false,
                    Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                    Poll::Pending => write_would_block = true,
                }
            }

            while !self.eof && self.session.wants_read() {
                match self.read_io(cx) {
                    Poll::Ready(Ok(0)) => self.eof = true,
                    Poll::Ready(Ok(n)) => rdlen += n,
                    Poll::Pending => {
                        read_would_block = true;
                        break;
                    }
                    Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                }
            }

            return match (self.eof, self.session.is_handshaking()) {
                (true, true) => {
                    let err = io::Error::new(io::ErrorKind::UnexpectedEof, "tls handshake eof");
                    Poll::Ready(Err(err))
                }
                (_, false) => Poll::Ready(Ok((rdlen, wrlen))),
                (_, true) if write_would_block || read_would_block => {
                    if rdlen != 0 || wrlen != 0 {
                        Poll::Ready(Ok((rdlen, wrlen)))
                    } else {
                        Poll::Pending
                    }
                }
                (..) => continue,
            };
        }
    }

    pub(crate) fn poll_fill_buf(mut self, cx: &mut Context<'_>) -> Poll<io::Result<&'a [u8]>> {
        if !self.plaintext.is_empty() {
            return Poll::Ready(Ok(self.plaintext.pending()));
        }

        let mut io_pending = false;

        // read a packet
        while self.plaintext.is_empty() && !self.eof && self.session.wants_read() {
            match self.read_io(cx) {
                Poll::Ready(Ok(0)) => {
                    self.eof = true;
                    break;
                }
                Poll::Ready(Ok(_)) => (),
                Poll::Pending => {
                    io_pending = true;
                    break;
                }
                Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
            }
        }

        if !self.plaintext.is_empty() {
            return Poll::Ready(Ok(self.plaintext.pending()));
        }

        if self.eof {
            return if self.session.wants_read() {
                Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "peer closed connection without sending TLS close_notify",
                )))
            } else {
                Poll::Ready(Ok(self.plaintext.pending()))
            };
        }

        if !self.session.wants_read() {
            // A close_notify with no remaining plaintext is a clean EOF.
            return Poll::Ready(Ok(self.plaintext.pending()));
        }

        if !io_pending {
            // No operation registered this task's waker. Arrange another poll in
            // case the connection made internal progress without yielding data.
            cx.waker().wake_by_ref();
        }

        Poll::Pending
    }
}

impl<'a, IO: AsyncRead + AsyncWrite + Unpin, C> AsyncRead for Stream<'a, IO, C>
where
    C: RustlsConnection + 'a,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let data = ready!(self.as_mut().poll_fill_buf(cx))?;
        let amount = buf.remaining().min(data.len());
        buf.put_slice(&data[..amount]);
        self.plaintext.consume(amount);
        Poll::Ready(Ok(()))
    }
}

impl<'a, IO: AsyncRead + AsyncWrite + Unpin, C> AsyncBufRead for Stream<'a, IO, C>
where
    C: RustlsConnection + 'a,
{
    fn poll_fill_buf(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<&[u8]>> {
        let this = self.get_mut();
        Stream {
            // reborrow
            io: this.io,
            session: this.session,
            input: this.input,
            tls: this.tls,
            plaintext: this.plaintext,
            eof: this.eof,
            need_flush: this.need_flush,
        }
        .poll_fill_buf(cx)
    }

    fn consume(mut self: Pin<&mut Self>, amt: usize) {
        self.plaintext.consume(amt);
    }
}

impl<IO: AsyncRead + AsyncWrite + Unpin, C> AsyncWrite for Stream<'_, IO, C>
where
    C: RustlsConnection,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }

        // Do not grow the caller-owned TLS output buffer without bound. Pending
        // output must make progress before we accept more plaintext.
        while !self.tls.is_empty() {
            match self.write_io(cx) {
                Poll::Ready(Ok(0)) | Poll::Pending => return Poll::Pending,
                Poll::Ready(Ok(_)) => {}
                Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
            }
        }

        let len = buf.len().min(DEFAULT_BUFFER_LIMIT);
        let this = &mut *self;
        if let Err(err) = this
            .session
            .write_tls((&buf[..len]).into(), this.tls.append_vec())
        {
            return Poll::Ready(Err(io::Error::new(io::ErrorKind::InvalidData, err)));
        }

        // The plaintext has been accepted even when the socket now blocks. The
        // generated TLS bytes remain in `tls` for the next poll.
        while !self.tls.is_empty() {
            match self.write_io(cx) {
                Poll::Ready(Ok(0)) | Poll::Pending | Poll::Ready(Err(_)) => break,
                Poll::Ready(Ok(_)) => {}
            }
        }

        Poll::Ready(Ok(len))
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        if bufs.iter().all(|buf| buf.is_empty()) {
            return Poll::Ready(Ok(0));
        }

        while !self.tls.is_empty() {
            match self.write_io(cx) {
                Poll::Ready(Ok(0)) | Poll::Pending => return Poll::Pending,
                Poll::Ready(Ok(_)) => {}
                Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
            }
        }

        let mut available = DEFAULT_BUFFER_LIMIT;
        let slices: Vec<&[u8]> = bufs
            .iter()
            .map(|buf| {
                let take = buf.len().min(available);
                available -= take;
                &buf[..take]
            })
            .collect();
        let written = slices.iter().map(|buf| buf.len()).sum();
        let this = &mut *self;
        if let Err(err) = this
            .session
            .write_tls(OutboundPlain::new(&slices), this.tls.append_vec())
        {
            return Poll::Ready(Err(io::Error::new(io::ErrorKind::InvalidData, err)));
        }

        while !self.tls.is_empty() {
            match self.write_io(cx) {
                Poll::Ready(Ok(0)) | Poll::Pending | Poll::Ready(Err(_)) => break,
                Poll::Ready(Ok(_)) => {}
            }
        }

        Poll::Ready(Ok(written))
    }

    #[inline]
    fn is_write_vectored(&self) -> bool {
        true
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<io::Result<()>> {
        while !self.tls.is_empty() {
            if ready!(self.write_io(cx))? == 0 {
                return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
            }
        }

        match Pin::new(&mut self.io).poll_flush(cx) {
            Poll::Ready(Ok(())) => {
                self.need_flush = false;
                Poll::Ready(Ok(()))
            }
            poll => poll,
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while !self.tls.is_empty() {
            if ready!(self.write_io(cx))? == 0 {
                return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
            }
        }

        Poll::Ready(match ready!(Pin::new(&mut self.io).poll_shutdown(cx)) {
            Ok(()) => Ok(()),
            // When trying to shutdown, not being connected seems fine
            Err(err) if err.kind() == io::ErrorKind::NotConnected => Ok(()),
            Err(err) => Err(err),
        })
    }
}

/// An adapter that implements a [`Read`] interface for [`AsyncRead`] types and an
/// associated [`Context`].
///
/// Turns `Poll::Pending` into `WouldBlock`.
pub(crate) struct SyncReadAdapter<'a, 'b, T> {
    pub(crate) io: &'a mut T,
    pub(crate) cx: &'a mut Context<'b>,
}

impl<T: AsyncRead + Unpin> Read for SyncReadAdapter<'_, '_, T> {
    #[inline]
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let mut buf = ReadBuf::new(buf);
        match Pin::new(&mut self.io).poll_read(self.cx, &mut buf) {
            Poll::Ready(Ok(())) => Ok(buf.filled().len()),
            Poll::Ready(Err(err)) => Err(err),
            Poll::Pending => Err(io::ErrorKind::WouldBlock.into()),
        }
    }
}

/// An adapter that implements a [`Write`] interface for [`AsyncWrite`] types and an
/// associated [`Context`].
///
/// Turns `Poll::Pending` into `WouldBlock`.
pub(crate) struct SyncWriteAdapter<'a, 'b, T> {
    pub(crate) io: &'a mut T,
    pub(crate) cx: &'a mut Context<'b>,
}

impl<T: Unpin> SyncWriteAdapter<'_, '_, T> {
    #[inline]
    fn poll_with<U>(
        &mut self,
        f: impl FnOnce(Pin<&mut T>, &mut Context<'_>) -> Poll<io::Result<U>>,
    ) -> io::Result<U> {
        match f(Pin::new(self.io), self.cx) {
            Poll::Ready(result) => result,
            Poll::Pending => Err(io::ErrorKind::WouldBlock.into()),
        }
    }
}

impl<T: AsyncWrite + Unpin> Write for SyncWriteAdapter<'_, '_, T> {
    #[inline]
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.poll_with(|io, cx| io.poll_write(cx, buf))
    }

    #[inline]
    fn write_vectored(&mut self, bufs: &[IoSlice<'_>]) -> io::Result<usize> {
        self.poll_with(|io, cx| io.poll_write_vectored(cx, bufs))
    }

    fn flush(&mut self) -> io::Result<()> {
        self.poll_with(|io, cx| io.poll_flush(cx))
    }
}

#[cfg(test)]
mod cursor_vec_tests {
    use super::CursorVec;

    #[test]
    fn preserves_pending_bytes_across_compaction() {
        let mut buffer = CursorVec::from_vec(b"abcdef".to_vec());
        buffer.consume(2);
        buffer.append_vec().extend_from_slice(b"gh");
        buffer.consume(3);
        buffer.append_vec().extend_from_slice(b"ij");

        assert_eq!(buffer.pending(), b"fghij");
        assert_eq!(buffer.into_pending_vec(), b"fghij");
    }

    #[test]
    fn repeated_small_consumption_and_append_keeps_storage_bounded() {
        let mut buffer = CursorVec::from_vec(vec![0, 1]);

        for byte in 2..=u8::MAX {
            buffer.consume(1);
            buffer.append_vec().push(byte);

            assert_eq!(buffer.len(), 2);
            assert!(buffer.bytes.len() <= 2 * buffer.len());
        }

        assert_eq!(buffer.pending(), &[u8::MAX - 1, u8::MAX]);
    }

    #[test]
    fn debug_only_shows_pending_bytes() {
        let mut buffer = CursorVec::from_vec(vec![1, 2, 3]);
        buffer.consume(2);

        assert_eq!(format!("{buffer:?}"), "[3]");
    }
}

#[cfg(test)]
mod test_stream;
