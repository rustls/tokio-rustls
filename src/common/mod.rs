use std::io::{self, IoSlice};
use std::pin::Pin;
use std::task::{Context, Poll};

use rustls::SideData;
use rustls::crypto::cipher::OutboundPlain;
use tokio::io::{AsyncBufRead, AsyncRead, AsyncWrite, ReadBuf};

mod handshake;
pub(crate) use handshake::{IoSession, MidHandshake};

use crate::{Buffered, TLS_BUFFER_LIMIT};

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

pub(crate) struct Stream<'a, IO, SD: SideData> {
    pub(crate) io: &'a mut IO,
    pub(crate) buffered: &'a mut Buffered<SD>,
    pub(crate) need_flush: bool,
}

impl<'a, IO: AsyncRead + AsyncWrite + Unpin, SD: SideData> Stream<'a, IO, SD> {
    pub(crate) fn new(io: &'a mut IO, buffered: &'a mut Buffered<SD>) -> Self {
        Stream {
            io,
            buffered,
            // Whether a previous flush returned pending, or a write occured without a flush.
            need_flush: false,
        }
    }

    pub(crate) fn set_need_flush(mut self, need_flush: bool) -> Self {
        self.need_flush = need_flush;
        self
    }

    pub(crate) fn as_mut_pin(&mut self) -> Pin<&mut Self> {
        Pin::new(self)
    }

    pub(crate) fn read_io(&mut self, cx: &mut Context) -> Poll<io::Result<usize>> {
        let mut buf = match self.buffered.read_buf() {
            Ok(buf) => buf,
            Err(err) => return Poll::Ready(Err(err)),
        };

        let read = match ready!(Pin::new(&mut self.io).poll_read(cx, &mut buf)) {
            Ok(()) => buf.filled().len(),
            Err(err) => return Poll::Ready(Err(err)),
        };

        self.buffered.used += read;
        if read == 0 {
            self.buffered.has_seen_eof = true;
        }

        let error = match self.buffered.process_input() {
            Ok(_) => return Poll::Ready(Ok(read)),
            Err(err) => err,
        };

        // In case we have an alert to send describing this error,
        // try a last-gasp write -- but don't predate the primary
        // error.
        let _ = self.write_io(cx);
        Poll::Ready(Err(io::Error::new(io::ErrorKind::InvalidData, error)))
    }

    pub(crate) fn write_io(&mut self, cx: &mut Context) -> Poll<io::Result<usize>> {
        let io = Pin::new(&mut self.io);
        let written = match ready!(io.poll_write(cx, &self.buffered.tls)) {
            Ok(written) => written,
            Err(err) => return Poll::Ready(Err(err)),
        };

        self.buffered.tls.copy_within(written.., 0);
        self.buffered
            .tls
            .truncate(self.buffered.tls.len() - written);
        Poll::Ready(Ok(written))
    }

    /// Writes out buffered TLS data until there is room to encrypt more plaintext
    fn poll_tls_room(&mut self, cx: &mut Context) -> Poll<io::Result<usize>> {
        while self.buffered.tls.len() >= TLS_BUFFER_LIMIT {
            if ready!(self.write_io(cx))? == 0 {
                return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
            }
        }

        Poll::Ready(Ok(TLS_BUFFER_LIMIT - self.buffered.tls.len()))
    }

    /// Writes out buffered TLS data for as long as the transport accepts it without blocking
    fn try_write_tls(&mut self, cx: &mut Context) -> io::Result<()> {
        while !self.buffered.tls.is_empty() {
            match self.write_io(cx) {
                Poll::Ready(Ok(0)) | Poll::Pending => break,
                Poll::Ready(Ok(_)) => (),
                Poll::Ready(Err(err)) => return Err(err),
            }
        }

        Ok(())
    }

    pub(crate) fn handshake(&mut self, cx: &mut Context) -> Poll<io::Result<(usize, usize)>> {
        let mut wrlen = 0;
        let mut rdlen = 0;

        loop {
            let mut write_would_block = false;
            let mut read_would_block = false;

            while !self.buffered.tls.is_empty() {
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

            while self.buffered.wants_read() {
                match self.read_io(cx) {
                    Poll::Ready(Ok(n)) => rdlen += n,
                    Poll::Pending => {
                        read_would_block = true;
                        break;
                    }
                    Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                }
            }

            let eof = self.buffered.has_seen_eof || self.buffered.received_close_notify;
            return match (eof, self.buffered.conn.is_handshaking()) {
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

    pub(crate) fn poll_fill_buf(mut self, cx: &mut Context<'_>) -> Poll<io::Result<&'a [u8]>>
    where
        SD: 'a,
    {
        while self.buffered.wants_read() {
            match self.read_io(cx) {
                Poll::Ready(Ok(_)) => (),
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
            }
        }

        // Plaintext is available, or the peer has closed the connection
        if self.buffered.received_plaintext.is_empty() && !self.buffered.received_close_notify {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "peer closed connection without sending TLS close_notify",
            )));
        }

        // Note that this is empty (i.e. EOF) if a `close_notify` was received and there is no
        // more buffered plaintext.
        Poll::Ready(Ok(self.buffered.received_plaintext.as_slice()))
    }
}

impl<'a, IO: AsyncRead + AsyncWrite + Unpin, SD> AsyncRead for Stream<'a, IO, SD>
where
    SD: SideData + 'a,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let data = ready!(self.as_mut().poll_fill_buf(cx))?;
        let amount = buf.remaining().min(data.len());
        buf.put_slice(&data[..amount]);
        self.consume(amount);
        Poll::Ready(Ok(()))
    }
}

impl<'a, IO: AsyncRead + AsyncWrite + Unpin, SD> AsyncBufRead for Stream<'a, IO, SD>
where
    SD: SideData + 'a,
{
    fn poll_fill_buf(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<&[u8]>> {
        let this = self.get_mut();
        Stream {
            // reborrow
            io: this.io,
            buffered: this.buffered,
            ..*this
        }
        .poll_fill_buf(cx)
    }

    fn consume(mut self: Pin<&mut Self>, amt: usize) {
        let new_len = self.buffered.received_plaintext.len() - amt;
        self.buffered.received_plaintext.copy_within(amt.., 0);
        self.buffered.received_plaintext.truncate(new_len);
    }
}

impl<IO: AsyncRead + AsyncWrite + Unpin, SD> AsyncWrite for Stream<'_, IO, SD>
where
    SD: SideData,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }

        let room = ready!(self.poll_tls_room(cx))?;
        let written = Ord::min(buf.len(), room);
        let buffered = &mut *self.buffered;
        if let Err(err) = buffered
            .conn
            .write(OutboundPlain::from(&buf[..written]), &mut buffered.tls)
        {
            return Poll::Ready(Err(io::Error::other(err)));
        };

        self.try_write_tls(cx)?;
        Poll::Ready(Ok(written))
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        let (mut chunks, mut non_empty, mut end) =
            (Vec::<&[u8]>::with_capacity(bufs.len()), false, 0);
        for buf in bufs {
            if buf.is_empty() {
                continue;
            }

            chunks.push(&*buf);
            non_empty |= true;
            end += buf.len();
        }

        if !non_empty {
            return Poll::Ready(Ok(0));
        }

        let room = ready!(self.poll_tls_room(cx))?;
        let end = Ord::min(end, room);
        let plaintext = OutboundPlain::Multiple {
            chunks: &chunks,
            start: 0,
            end,
        };

        let buffered = &mut *self.buffered;
        if let Err(err) = buffered.conn.write(plaintext, &mut buffered.tls) {
            return Poll::Ready(Err(io::Error::other(err)));
        };

        self.try_write_tls(cx)?;
        Poll::Ready(Ok(end))
    }

    #[inline]
    fn is_write_vectored(&self) -> bool {
        true
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<io::Result<()>> {
        while !self.buffered.tls.is_empty() {
            if ready!(self.write_io(cx))? == 0 {
                return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
            }
        }

        Pin::new(&mut self.io).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while !self.buffered.tls.is_empty() {
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

#[cfg(test)]
mod test_stream;
