use std::{
    borrow::Cow,
    io,
    mem::MaybeUninit,
    pin::Pin,
    task::{Context, Poll, ready},
};

use compio::{
    io::{AsyncRead, AsyncWrite, compat::AsyncStream, util::Splittable},
    tls::{MaybeTlsStream, TlsStream},
};
use send_wrapper::SendWrapper;

/// Base capacity for the plain-stream read adapter, and the maximum slice of
/// hyper's read cursor initialised per `poll_read`.
///
/// compio drains the socket into an internal buffer that is compacted back to
/// this base capacity on every read (its upstream default is only 8 KiB), so it
/// reads at most ~`READ_CHUNK` bytes per poll. hyper, meanwhile, grows its read
/// cursor toward ~400 KiB for large bodies. The upstream adapter zero-filled the
/// *entire* cursor before every short compio read, so the per-read memset scaled
/// with the cursor rather than the bytes transferred — an overhead that grew
/// with body size and dominated large-body throughput. Reading in `READ_CHUNK`
/// chunks and only initialising that much of the cursor keeps the zero-fill ~1x
/// the data actually read.
const READ_CHUNK: usize = 256 * 1024;

/// A stream wrapper for hyper.
#[derive(Debug)]
pub struct HyperStream<S: Splittable>(SendWrapper<MaybeTlsStream<S>>);

impl<S: Splittable> HyperStream<S> {
    /// Create a new [`HyperStream`] from a plain stream.
    pub fn new_plain(s: S) -> Self {
        // Build the compio->futures read adapter with a large base capacity so
        // the socket is drained in `READ_CHUNK` chunks instead of compio's 8 KiB
        // default — far fewer reads, copies, and cursor round-trips per body.
        let stream = AsyncStream::with_capacity(READ_CHUNK, s);
        Self(SendWrapper::new(MaybeTlsStream::new_plain_compat(stream)))
    }

    /// Create a new [`HyperStream`] from a TLS stream.
    pub fn new_tls(s: TlsStream<S>) -> Self {
        Self(SendWrapper::new(MaybeTlsStream::new_tls(s)))
    }

    /// Whether the stream is TLS-encrypted.
    pub fn is_tls(&self) -> bool {
        self.0.is_tls()
    }
}

impl<S: Splittable + 'static> HyperStream<S>
where
    S::ReadHalf: AsyncRead + Unpin,
    S::WriteHalf: AsyncWrite + Unpin,
{
    /// Returns the negotiated ALPN protocol.
    pub fn negotiated_alpn(&self) -> Option<Cow<'_, [u8]>> {
        self.0.negotiated_alpn()
    }
}

impl<S: Splittable + 'static> hyper::rt::Read for HyperStream<S>
where
    S::ReadHalf: AsyncRead + Unpin,
    S::WriteHalf: AsyncWrite + Unpin,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        mut buf: hyper::rt::ReadBufCursor<'_>,
    ) -> Poll<io::Result<()>> {
        let uninit = unsafe { buf.as_mut() };
        // Only initialise and offer up to `READ_CHUNK` of hyper's cursor: compio
        // delivers at most that much per poll, so zero-filling the whole (up to
        // ~400 KiB, body-size-scaled) cursor every read is wasted memset. See
        // `READ_CHUNK`.
        let len = uninit.len().min(READ_CHUNK);
        let slice = &mut uninit[..len];
        slice.fill(MaybeUninit::new(0));
        // SAFETY: the first `len` bytes were just initialised by `fill`.
        let init = unsafe { std::slice::from_raw_parts_mut(slice.as_mut_ptr().cast::<u8>(), len) };
        let res = ready!(futures_util::AsyncRead::poll_read(
            Pin::new(&mut *self.0),
            cx,
            init
        ))?;
        unsafe { buf.advance(res) };
        Poll::Ready(Ok(()))
    }
}

impl<S: Splittable + 'static> futures_util::AsyncRead for HyperStream<S>
where
    S::ReadHalf: AsyncRead + Unpin,
    S::WriteHalf: AsyncWrite + Unpin,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        futures_util::AsyncRead::poll_read(Pin::new(&mut *self.0), cx, buf)
    }

    fn poll_read_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &mut [io::IoSliceMut<'_>],
    ) -> Poll<io::Result<usize>> {
        futures_util::AsyncRead::poll_read_vectored(Pin::new(&mut *self.0), cx, bufs)
    }
}

impl<S: Splittable + 'static> hyper::rt::Write for HyperStream<S>
where
    S::ReadHalf: AsyncRead + Unpin,
    S::WriteHalf: AsyncWrite + Unpin,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        futures_util::AsyncWrite::poll_write(Pin::new(&mut *self.0), cx, buf)
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        futures_util::AsyncWrite::poll_write_vectored(Pin::new(&mut *self.0), cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        true
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        futures_util::AsyncWrite::poll_flush(Pin::new(&mut *self.0), cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        futures_util::AsyncWrite::poll_close(Pin::new(&mut *self.0), cx)
    }
}

impl<S: Splittable + 'static> futures_util::AsyncWrite for HyperStream<S>
where
    S::ReadHalf: AsyncRead + Unpin,
    S::WriteHalf: AsyncWrite + Unpin,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        futures_util::AsyncWrite::poll_write(Pin::new(&mut *self.0), cx, buf)
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        futures_util::AsyncWrite::poll_write_vectored(Pin::new(&mut *self.0), cx, bufs)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        futures_util::AsyncWrite::poll_flush(Pin::new(&mut *self.0), cx)
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        futures_util::AsyncWrite::poll_close(Pin::new(&mut *self.0), cx)
    }
}
