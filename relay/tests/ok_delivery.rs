mod common;
use common::*;
use futures_util::task::AtomicWaker;
use std::{
    io,
    net::SocketAddr,
    pin::Pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    task::{Context, Poll},
};
use tau_relay::*;
use tokio::{
    io::{AsyncRead, AsyncWrite, AsyncWriteExt, DuplexStream, ReadBuf, duplex},
    sync::Notify,
};
use tokio_tungstenite::tungstenite::Message;

#[derive(Default)]
struct Gate {
    blocked: AtomicBool,
    waker: AtomicWaker,
    waiting: Notify,
}
struct OutputGate {
    inner: DuplexStream,
    gate: Arc<Gate>,
}
impl AsyncRead for OutputGate {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}
impl AsyncWrite for OutputGate {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.gate.waker.register(cx.waker());
        if self.gate.blocked.load(Ordering::SeqCst) {
            self.gate.waiting.notify_one();
            return Poll::Pending;
        }
        Pin::new(&mut self.inner).poll_write(cx, bytes)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}
struct Watched {
    inner: DuplexStream,
    reads: Arc<AtomicUsize>,
    writes: Arc<AtomicUsize>,
}
impl AsyncRead for Watched {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        self.reads.fetch_add(1, Ordering::SeqCst);
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}
impl AsyncWrite for Watched {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.writes.fetch_add(bytes.len(), Ordering::SeqCst);
        Pin::new(&mut self.inner).poll_write(cx, bytes)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}
struct Dial(Mutex<Option<Watched>>);
impl Dialer for Dial {
    fn dial(&self, _: SocketAddr) -> BoxFuture<'_, io::Result<Tcp>> {
        Box::pin(async move { Ok(Box::new(self.0.lock().unwrap().take().unwrap()) as Tcp) })
    }
}
#[tokio::test]
async fn no_banner_read_or_application_write_while_ok_is_blocked() {
    for (early_binary, fin, simultaneous) in [
        (false, true, false),
        (true, true, false),
        (true, false, false),
        (true, false, true),
        (true, true, true),
    ] {
        let mut f = Fixture::new();
        let (tcp, mut peer) = duplex(4096);
        let reads = Arc::new(AtomicUsize::new(0));
        let writes = Arc::new(AtomicUsize::new(0));
        f.relay.dialer = Arc::new(Dial(Mutex::new(Some(Watched {
            inner: tcp,
            reads: reads.clone(),
            writes: writes.clone(),
        }))));
        peer.write_all(b"banner").await.unwrap();
        let gate = Arc::new(Gate::default());
        let (server, client) = duplex(4096);
        let relay = Arc::new(f.relay);
        let task = tokio::spawn({
            let gate = gate.clone();
            async move {
                connection(
                    OutputGate {
                        inner: server,
                        gate,
                    },
                    &relay,
                )
                .await
            }
        });
        let (mut ws, _) =
            tokio_tungstenite::client_async(format!("ws://localhost/v1/tcp/{HOST}/22"), client)
                .await
                .unwrap();
        let c = challenge(&mut ws).await;
        gate.blocked.store(true, Ordering::SeqCst);
        send(&mut ws, signed(&c, HOST, 22, NOW, 7)).await;
        tokio::time::timeout(std::time::Duration::from_secs(2), gate.waiting.notified())
            .await
            .unwrap();
        assert_eq!(reads.load(Ordering::SeqCst), 0);
        assert_eq!(writes.load(Ordering::SeqCst), 0);
        if early_binary {
            raw_data(
                &mut ws,
                tokio_tungstenite::tungstenite::protocol::frame::coding::Data::Binary,
                fin,
                b"early",
            )
            .await;
            if !simultaneous {
                tokio::time::timeout(std::time::Duration::from_secs(2), gate.waiting.notified())
                    .await
                    .unwrap();
            }
        }
        gate.blocked.store(false, Ordering::SeqCst);
        gate.waker.wake();
        if early_binary {
            // OK may already be queued in the output buffer; no application data
            // can be consumed as a result of that partially completed send.
            match frame(&mut ws).await {
                Message::Text(text) => {
                    assert_eq!(
                        serde_json::from_str::<serde_json::Value>(&text).unwrap(),
                        serde_json::json!({"ok":true})
                    );
                    closed(&mut ws, 1002).await;
                }
                Message::Close(Some(c)) => assert_eq!(u16::from(c.code), 1002),
                other => panic!("unexpected frame: {other:?}"),
            }
            task.await.unwrap();
            assert_eq!(reads.load(Ordering::SeqCst), 0);
            assert_eq!(writes.load(Ordering::SeqCst), 0);
        } else {
            verdict(&mut ws, serde_json::json!({"ok":true})).await;
            assert_eq!(frame(&mut ws).await, Message::binary(b"banner".to_vec()));
            ws.close(None).await.unwrap();
            task.await.unwrap();
        }
    }
}
