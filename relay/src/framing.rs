//! Limit reads to frame boundaries so reassembly cannot hide premature data.
use std::{
    io::{self, Cursor},
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicU8, Ordering},
    },
    task::{Context, Poll, ready},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_tungstenite::tungstenite::protocol::frame::FrameHeader;

pub const AUTH: u8 = 0;
pub const WAIT_OK: u8 = 1;
pub const OPEN: u8 = 2;

pub struct Guard<S> {
    inner: S,
    pub phase: Arc<AtomicU8>,
    upgrade_tail: u32,
    upgrade: Vec<u8>,
    upgrade_sent: usize,
    upgraded: bool,
    header: Vec<u8>,
    remaining: u64,
}
impl<S> Guard<S> {
    pub fn new(inner: S) -> Self {
        Self {
            inner,
            phase: Arc::new(AtomicU8::new(AUTH)),
            upgrade_tail: 0,
            upgrade: Vec::new(),
            upgrade_sent: 0,
            upgraded: false,
            header: Vec::with_capacity(14),
            remaining: 0,
        }
    }
}
impl<S: AsyncRead + Unpin> AsyncRead for Guard<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        // Collect the upgrade header before returning it in normal chunks. This
        // keeps normal chunk sizes for the library's HTTP parser without reading any
        // WebSocket bytes ahead of its phase checks.
        while !self.upgraded {
            let mut byte = [0];
            let mut one = ReadBuf::new(&mut byte);
            ready!(Pin::new(&mut self.inner).poll_read(cx, &mut one))?;
            if one.filled().is_empty() {
                return Poll::Ready(Ok(()));
            }
            if self.upgrade.len() >= crate::PocLimits::UPGRADE {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "upgrade too large",
                )));
            }
            self.upgrade.push(byte[0]);
            self.upgrade_tail = (self.upgrade_tail << 8) | u32::from(byte[0]);
            self.upgraded = self.upgrade_tail == u32::from_be_bytes(*b"\r\n\r\n");
        }
        if self.upgrade_sent < self.upgrade.len() {
            let end = (self.upgrade_sent + buf.remaining()).min(self.upgrade.len());
            buf.put_slice(&self.upgrade[self.upgrade_sent..end]);
            self.upgrade_sent = end;
            if end == self.upgrade.len() {
                self.upgrade = Vec::new();
                self.upgrade_sent = 0;
            }
            return Poll::Ready(Ok(()));
        }
        if self.remaining > 0 {
            let n = self.remaining.min(buf.remaining() as u64) as usize;
            let mut limited = ReadBuf::new(buf.initialize_unfilled_to(n));
            ready!(Pin::new(&mut self.inner).poll_read(cx, &mut limited))?;
            let n = limited.filled().len();
            buf.advance(n);
            self.remaining -= n as u64;
            return Poll::Ready(Ok(()));
        }
        // Never let the upgrade parser or reassembler prefetch a later frame.
        // Only the header is inspected here; the WebSocket library still owns
        // masking, fragmentation, controls, validation and message limits.
        let mut byte = [0];
        let mut one = ReadBuf::new(&mut byte);
        ready!(Pin::new(&mut self.inner).poll_read(cx, &mut one))?;
        if one.filled().is_empty() {
            return Poll::Ready(Ok(()));
        }
        let b = byte[0];
        if self.header.is_empty() {
            let opcode = b & 0x0f;
            let phase = self.phase.load(Ordering::SeqCst);
            let forbidden = match phase {
                AUTH => opcode == 2,
                WAIT_OK => opcode <= 2,
                _ => opcode == 1,
            };
            if forbidden {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "unexpected data frame",
                )));
            }
        }
        self.header.push(b);
        match FrameHeader::parse(&mut Cursor::new(&self.header)) {
            Ok(Some((_, length))) => {
                self.remaining = length;
                self.header.clear();
            }
            Ok(None) => {}
            Err(_) => {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid frame header",
                )));
            }
        }
        buf.put_slice(&byte);
        Poll::Ready(Ok(()))
    }
}
impl<S: AsyncWrite + Unpin> AsyncWrite for Guard<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}
