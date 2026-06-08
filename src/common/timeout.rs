use std::future::Future;
use std::io;
use std::ops::{Deref, DerefMut};
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use rustls::{ConnectionCommon, SideData};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::time::{sleep, Sleep};

use crate::common::{IoSession, MidHandshake};

/// A `MidHandshake` future bundled with an optional deadline.
pub(crate) struct HandshakeFuture<IS: IoSession> {
    inner: MidHandshake<IS>,
    timeout: Option<Timeout>,
}

impl<IS: IoSession> HandshakeFuture<IS> {
    pub(crate) fn new(inner: MidHandshake<IS>, timeout: Option<Duration>) -> Self {
        Self {
            inner,
            timeout: timeout.map(|duration| Timeout {
                duration,
                sleep: None,
            }),
        }
    }

    pub(crate) fn handshake(&self) -> &MidHandshake<IS> {
        &self.inner
    }

    pub(crate) fn handshake_mut(&mut self) -> &mut MidHandshake<IS> {
        &mut self.inner
    }
}

impl<IS, SD> HandshakeFuture<IS>
where
    IS: IoSession + Unpin,
    IS::Io: AsyncRead + AsyncWrite + Unpin,
    IS::Session: DerefMut + Deref<Target = ConnectionCommon<SD>> + Unpin,
    SD: SideData,
{
    pub(crate) fn poll(&mut self, cx: &mut Context<'_>) -> Poll<Result<IS, (io::Error, IS::Io)>> {
        if let Poll::Ready(result) = Pin::new(&mut self.inner).poll(cx) {
            return Poll::Ready(result);
        }

        let timeout = match &mut self.timeout {
            Some(timeout) => timeout,
            None => return Poll::Pending,
        };

        let sleep = timeout
            .sleep
            .get_or_insert_with(|| Box::pin(sleep(timeout.duration)));
        if sleep.as_mut().poll(cx).is_pending() {
            return Poll::Pending;
        }

        match self.inner.take_io() {
            Some(io) => Poll::Ready(Err((
                io::Error::new(io::ErrorKind::TimedOut, "TLS handshake timed out"),
                io,
            ))),
            // The inner handshake just returned `Pending` above, so it must
            // still hold its IO because `take_io()` only returns `None` for the
            // `End` state, which `MidHandshake::poll` never leaves behind
            // when returning `Pending`.
            None => unreachable!("handshake returned Pending but has no IO"),
        }
    }
}

struct Timeout {
    duration: Duration,
    sleep: Option<Pin<Box<Sleep>>>,
}
