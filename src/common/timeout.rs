use std::future::Future;
use std::io;
use std::ops::{Deref, DerefMut};
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use rustls::{ConnectionCommon, SideData};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::time::{Instant, Sleep, sleep_until};

use crate::common::{IoSession, MidHandshake};

/// A `MidHandshake` future bundled with an optional deadline.
pub(crate) struct HandshakeFuture<IS: IoSession> {
    inner: MidHandshake<IS>,
    timeout: Option<Timeout>,
}

impl<IS: IoSession> HandshakeFuture<IS> {
    /// Construct with a relative `Duration` timeout.
    ///
    /// The deadline is fixed to `Instant::now() + duration` immediately, so the
    /// clock starts ticking when this is called, not when the future is first polled.
    pub(crate) fn new(inner: MidHandshake<IS>, timeout: Option<Duration>) -> Self {
        Self {
            inner,
            timeout: timeout.map(Timeout::from_duration),
        }
    }

    /// Construct with an absolute `Instant` deadline.
    ///
    /// Used when an earlier phase (e.g. `LazyConfigAcceptor`) already established the
    /// deadline and the post-ClientHello phase needs to inherit it.
    pub(crate) fn from_deadline(inner: MidHandshake<IS>, deadline: Option<Instant>) -> Self {
        Self {
            inner,
            timeout: deadline.map(Timeout::from_deadline),
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
        if timeout.poll_deadline(cx).is_pending() {
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

/// An absolute deadline paired with a lazily-initialized `Sleep` future.
pub(crate) struct Timeout {
    deadline: Instant,
    sleep: Option<Pin<Box<Sleep>>>,
}

impl Timeout {
    /// Construct from an absolute deadline.
    pub(crate) fn from_deadline(deadline: Instant) -> Self {
        Self {
            deadline,
            sleep: None,
        }
    }

    /// Construct from a relative duration.
    ///
    /// The deadline is fixed to `Instant::now() + duration` immediately.
    pub(crate) fn from_duration(duration: Duration) -> Self {
        Self::from_deadline(Instant::now() + duration)
    }

    /// Poll the deadline.
    ///
    /// Returns `Poll::Ready(())` once the deadline has elapsed; `Poll::Pending`
    /// otherwise. Lazily initializes the inner `Sleep` on first call.
    pub(crate) fn poll_deadline(&mut self, cx: &mut Context<'_>) -> Poll<()> {
        let sleep = self
            .sleep
            .get_or_insert_with(|| Box::pin(sleep_until(self.deadline)));
        sleep.as_mut().poll(cx)
    }

    /// Return the absolute deadline.
    pub(crate) fn deadline(&self) -> Instant {
        self.deadline
    }
}
