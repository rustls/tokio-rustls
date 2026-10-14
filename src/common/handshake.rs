use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::{io, mem};

use rustls::SideData;
use tokio::io::{AsyncRead, AsyncWrite};

use crate::Buffered;
use crate::common::{Stream, TlsState};

pub(crate) trait IoSession {
    type Io;
    type Side: SideData;

    fn skip_handshake(&self) -> bool;
    fn get_mut(
        &mut self,
    ) -> (
        &mut TlsState,
        &mut Self::Io,
        &mut Buffered<Self::Side>,
        &mut bool,
    );
    fn into_io(self) -> Self::Io;
}

pub(crate) enum MidHandshake<IS: IoSession> {
    Handshaking(IS),
    End,
    SendAlert {
        io: IS::Io,
        tls: Vec<u8>,
        error: io::Error,
    },
    Error {
        io: IS::Io,
        error: io::Error,
    },
}

impl<IS> Future for MidHandshake<IS>
where
    IS: IoSession + Unpin,
    IS::Io: AsyncRead + AsyncWrite + Unpin,
{
    type Output = Result<IS, (io::Error, IS::Io)>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();

        let mut stream = match mem::replace(this, Self::End) {
            Self::Handshaking(stream) => stream,
            Self::SendAlert {
                mut io,
                mut tls,
                error,
            } => loop {
                match ready!(Pin::new(&mut io).poll_write(cx, &tls)) {
                    Ok(0) => return Poll::Ready(Err((error, io))),
                    Ok(written) => {
                        tls.copy_within(written.., 0);
                        tls.truncate(tls.len() - written);
                        if tls.is_empty() {
                            return Poll::Ready(Err((error, io)));
                        }
                    }
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                        *this = Self::SendAlert { io, tls, error };
                        return Poll::Pending;
                    }
                    Err(_) => return Poll::Ready(Err((error, io))),
                };
            },
            // Starting the handshake returned an error; fail the future immediately.
            Self::Error { io, error } => return Poll::Ready(Err((error, io))),
            _ => panic!("unexpected polling after handshake"),
        };

        if !stream.skip_handshake() {
            let (_, io, buffered, need_flush) = stream.get_mut();
            let mut tls_stream = Stream::new(io, buffered).set_need_flush(*need_flush);

            macro_rules! try_poll {
                ( $e:expr ) => {
                    match $e {
                        Poll::Ready(Ok(x)) => x,
                        Poll::Ready(Err(err)) => return Poll::Ready(Err((err, stream.into_io()))),
                        Poll::Pending => {
                            *need_flush = tls_stream.need_flush;
                            *this = MidHandshake::Handshaking(stream);
                            return Poll::Pending;
                        }
                    }
                };
            }

            while tls_stream.buffered.conn.is_handshaking() {
                try_poll!(tls_stream.handshake(cx));
            }

            try_poll!(Pin::new(&mut tls_stream).poll_flush(cx));
        }

        Poll::Ready(Ok(stream))
    }
}
