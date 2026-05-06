//! Raw UDP shred receiver — single-threaded, core-pinned, zero-alloc hot loop.
//!
//! Binds ONE blocking UDP socket and owns the deshred pipeline inline on a
//! dedicated thread. The handler is a `FnMut` so the caller can thread a
//! mutable `DeshredEngine` and any fan-out channel sender into it without
//! ever crossing a mutex or allocating per-packet.
//!
//! We don't split across multiple sockets via `SO_REUSEPORT`: for Jito
//! shredstream the source 4-tuple collapses onto one hash bucket anyway,
//! and splitting would fragment per-slot tracker state (shreds for one slot
//! landing on different threads would each see a partial segment and never
//! flush). If CPU headroom becomes the bottleneck, the right move is
//! multi-queue NIC RSS at a lower layer, not multi-thread above it.
//!
//! ## Receive batching
//!
//! The recv loop uses `recvmmsg` with `MSG_WAITFORONE`. The kernel blocks
//! until at least one packet is queued, then drains up to `BATCH_SIZE`
//! more without blocking. This collapses the per-packet syscall overhead
//! during bursts (Jito ships shreds in 32-shred FEC blocks back-to-back)
//! while preserving the no-added-latency property of a single `recvmsg`
//! when the queue is empty.
//!
//! Pre-allocated state: a `Box<RecvBatch>` holds `BATCH_SIZE` MTU-sized
//! packet buffers, control-msg buffers, `iovec`s, and `mmsghdr`s. The
//! libc structs are wired up once at thread start so each `recvmmsg`
//! call only resets `msg_controllen` (which the kernel mutates).
//!
//! `SO_BUSY_POLL` is opt-in via `ReceiverConfig::busy_poll_us`. When >0 the
//! kernel busy-polls the NIC RX ring inside the recv syscall before
//! sleeping, trading CPU for first-packet latency.

use std::io::ErrorKind;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::os::fd::AsRawFd;
use std::sync::{
    atomic::{AtomicBool, AtomicU64, Ordering},
    Arc,
};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use anyhow::{Context, Result};
use socket2::{Domain, Protocol, Socket, Type};
use tracing::{debug, info, warn};

/// Solana per-shred wire MTU. Any UDP-delivered shred fits in 1232 bytes.
pub const MAX_SHRED_SIZE: usize = 1232;

#[derive(Debug, Clone)]
pub struct ReceiverConfig {
    /// Local `ip:port` to bind. Must match the port advertised upstream.
    pub bind: SocketAddr,
    /// Kernel `SO_RCVBUF` target (bytes). Silently capped at
    /// `net.core.rmem_max` unless `CAP_NET_ADMIN` (via `SO_RCVBUFFORCE`).
    pub recv_buffer_bytes: usize,
    /// CPU core id to pin the receiver thread to. `None` = no pin.
    pub pin_core: Option<usize>,
    /// `SO_BUSY_POLL` value in microseconds. `0` = disabled (default kernel
    /// behavior: sleep on IRQ). Non-zero = kernel busy-polls the NIC RX
    /// ring for up to N µs inside each recv syscall before sleeping.
    /// Trades CPU for first-packet latency. Typical value: 50.
    pub busy_poll_us: u32,
}

impl Default for ReceiverConfig {
    fn default() -> Self {
        Self {
            bind: SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 20_000),
            recv_buffer_bytes: 64 * 1024 * 1024,
            pin_core: None,
            busy_poll_us: 0,
        }
    }
}

/// Counters published by the recv thread. The thread keeps thread-local
/// mirrors and batches updates.
#[derive(Default)]
pub struct ReceiverStats {
    pub packets: AtomicU64,
    pub bytes: AtomicU64,
    pub recv_errors: AtomicU64,
}

pub struct ReceiverHandle {
    thread: Option<JoinHandle<()>>,
    pub stats: Arc<ReceiverStats>,
}

impl ReceiverHandle {
    pub fn join(mut self) {
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

/// Spawn the single receiver thread. The handler is invoked with a slice
/// into a reusable stack buffer — valid only for the duration of the call.
/// Copy out anything you need to keep before returning.
pub fn spawn_receiver<H>(
    cfg: ReceiverConfig,
    handler: H,
    exit: Arc<AtomicBool>,
) -> Result<ReceiverHandle>
where
    H: FnMut(&[u8]) + Send + 'static,
{
    let socket =
        build_socket(&cfg).with_context(|| format!("binding UDP socket on {}", cfg.bind))?;
    let bound = socket.local_addr()?;
    let stats = Arc::new(ReceiverStats::default());
    let stats_for_thread = stats.clone();
    let pin_core = cfg.pin_core;
    let rcvbuf_mib = cfg.recv_buffer_bytes / (1024 * 1024);
    let busy_poll_us = cfg.busy_poll_us;

    let thread = thread::Builder::new()
        .name("pb-shred-rx".into())
        .spawn(move || {
            if let Some(id) = pin_core {
                if core_affinity::set_for_current(core_affinity::CoreId { id }) {
                    info!(core = id, "receiver thread pinned");
                } else {
                    warn!(core = id, "failed to pin receiver thread");
                }
            }
            recv_loop(socket, handler, stats_for_thread, exit);
        })
        .context("spawning receiver thread")?;

    info!(
        %bound,
        rcvbuf_mib,
        pin = ?pin_core,
        busy_poll_us,
        "shred receiver online"
    );

    Ok(ReceiverHandle {
        thread: Some(thread),
        stats,
    })
}

fn build_socket(cfg: &ReceiverConfig) -> Result<UdpSocket> {
    let domain = if cfg.bind.is_ipv4() {
        Domain::IPV4
    } else {
        Domain::IPV6
    };
    let sock = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
    sock.set_reuse_address(true)?;

    if let Err(e) = sock.set_recv_buffer_size(cfg.recv_buffer_bytes) {
        warn!(error = %e, "SO_RCVBUF bump rejected; continuing with kernel default");
    }

    sock.set_nonblocking(false)?;
    sock.set_read_timeout(Some(Duration::from_millis(500)))?;
    sock.bind(&cfg.bind.into())?;

    let fd = sock.as_raw_fd();
    if cfg.busy_poll_us > 0 {
        if let Err(e) = setsockopt_int(fd, libc::SOL_SOCKET, libc::SO_BUSY_POLL, cfg.busy_poll_us as i32)
        {
            warn!(
                error = %e,
                requested = cfg.busy_poll_us,
                "SO_BUSY_POLL rejected; need CAP_NET_ADMIN or net.core.busy_poll sysctl"
            );
        } else {
            info!(us = cfg.busy_poll_us, "SO_BUSY_POLL enabled");
        }
    }
    Ok(sock.into())
}

/// Thin wrapper over `setsockopt` for integer-valued options. Returns an
/// `io::Error` carrying the kernel's `errno` on failure.
fn setsockopt_int(fd: i32, level: i32, name: i32, value: i32) -> std::io::Result<()> {
    let val: libc::c_int = value;
    // SAFETY: `&val` is a valid pointer to a `c_int`-sized region for the
    // duration of the syscall; `fd` is a live socket fd.
    let ret = unsafe {
        libc::setsockopt(
            fd,
            level,
            name,
            &val as *const _ as *const libc::c_void,
            std::mem::size_of_val(&val) as libc::socklen_t,
        )
    };
    if ret == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

/// Flush local stats to the shared `Arc` every N packets. Keeps the hot
/// path writing its own cache line only.
const FLUSH_EVERY: u64 = 1024;

/// `recvmmsg` batch size. Sized to match the Solana FEC block (32 data
/// shreds), which is the natural burst granularity from Jito. Bigger
/// batches don't help in practice — the queue rarely holds more than one
/// FEC block at a time — and add stack/cache pressure.
const BATCH_SIZE: usize = 32;

/// Pre-allocated batch state for `recvmmsg`. Pinned on the heap so the
/// pointers we wire into `mmsghdr.msg_iov` stay valid for the lifetime of
/// the receive thread.
///
/// SAFETY: do not move or drop while a `recvmmsg` call is in flight; do
/// not push to the inner vecs (they're capacity-fixed at construction).
struct RecvBatch {
    bufs: Box<[[u8; MAX_SHRED_SIZE]; BATCH_SIZE]>,
    iovecs: Box<[libc::iovec; BATCH_SIZE]>,
    msgs: Box<[libc::mmsghdr; BATCH_SIZE]>,
}

impl RecvBatch {
    fn new() -> Box<Self> {
        // Build on the heap directly to avoid blowing the thread stack
        // (BATCH_SIZE × MAX_SHRED_SIZE = ~40 KB just for `bufs`).
        let bufs: Box<[[u8; MAX_SHRED_SIZE]; BATCH_SIZE]> =
            Box::new([[0u8; MAX_SHRED_SIZE]; BATCH_SIZE]);
        // SAFETY: `iovec` and `mmsghdr` are POD; zeroed values are
        // legal placeholders we overwrite immediately below.
        let iovecs: Box<[libc::iovec; BATCH_SIZE]> =
            Box::new(unsafe { std::mem::zeroed() });
        let msgs: Box<[libc::mmsghdr; BATCH_SIZE]> =
            Box::new(unsafe { std::mem::zeroed() });
        let mut batch = Box::new(Self {
            bufs,
            iovecs,
            msgs,
        });
        batch.wire_pointers();
        batch
    }

    /// (Re-)point the libc structs at our owned buffers. Idempotent — safe
    /// to invoke whenever in doubt.
    fn wire_pointers(&mut self) {
        // Iovecs reference the packet buffers.
        for i in 0..BATCH_SIZE {
            let buf_ptr = self.bufs[i].as_mut_ptr() as *mut libc::c_void;
            self.iovecs[i] = libc::iovec {
                iov_base: buf_ptr,
                iov_len: MAX_SHRED_SIZE,
            };
        }
        let iovec_base = self.iovecs.as_mut_ptr();
        for i in 0..BATCH_SIZE {
            let m = &mut self.msgs[i];
            m.msg_hdr.msg_name = std::ptr::null_mut();
            m.msg_hdr.msg_namelen = 0;
            // SAFETY: iovec_base is the start of `self.iovecs`, valid for
            // the life of `self`; `i < BATCH_SIZE` so the pointer is
            // in-bounds.
            m.msg_hdr.msg_iov = unsafe { iovec_base.add(i) };
            m.msg_hdr.msg_iovlen = 1;
            m.msg_hdr.msg_control = std::ptr::null_mut();
            m.msg_hdr.msg_controllen = 0;
            m.msg_hdr.msg_flags = 0;
            m.msg_len = 0;
        }
    }
}

/// Out-of-line cold helper: log a recv error and bump the local counter.
/// Pulled out of the hot loop so steady-state recvs don't touch the warn
/// machinery's I-cache.
#[cold]
#[inline(never)]
fn note_recv_error(local_errs: &mut u64, err: std::io::Error) {
    *local_errs += 1;
    warn!(error = %err, "udp recvmmsg error");
}

fn recv_loop<H: FnMut(&[u8])>(
    socket: UdpSocket,
    mut handler: H,
    stats: Arc<ReceiverStats>,
    exit: Arc<AtomicBool>,
) {
    let mut batch = RecvBatch::new();
    let fd = socket.as_raw_fd();

    let mut local_pkts: u64 = 0;
    let mut local_bytes: u64 = 0;
    let mut local_errs: u64 = 0;
    let mut since_flush: u64 = 0;

    while !exit.load(Ordering::Relaxed) {
        // SAFETY: `batch.msgs` is a stable, BATCH_SIZE-long array; all
        // inner pointers were wired by `RecvBatch::new`. The kernel only
        // writes to `msg_len` and `msg_flags` per call — buf/iovec
        // pointers stay stable, so no per-call reset is needed.
        let n = unsafe {
            libc::recvmmsg(
                fd,
                batch.msgs.as_mut_ptr(),
                BATCH_SIZE as libc::c_uint,
                libc::MSG_WAITFORONE,
                std::ptr::null_mut(),
            )
        };
        if n < 0 {
            let err = std::io::Error::last_os_error();
            match err.kind() {
                // SO_RCVTIMEO fired — used as a shutdown poll trigger.
                ErrorKind::WouldBlock | ErrorKind::TimedOut => continue,
                _ => note_recv_error(&mut local_errs, err),
            }
            continue;
        }

        let n = n as usize;

        for i in 0..n {
            let m = &batch.msgs[i];
            let pkt_len = m.msg_len as usize;
            // SAFETY: kernel set `msg_len` to the byte count it wrote to
            // `bufs[i]`; bounded by `MAX_SHRED_SIZE` (the iovec we
            // exposed), so the slice is in-bounds.
            let buf: &[u8] = &batch.bufs[i][..pkt_len];

            local_pkts += 1;
            local_bytes += pkt_len as u64;
            handler(buf);
        }

        since_flush += n as u64;
        if since_flush >= FLUSH_EVERY {
            stats.packets.store(local_pkts, Ordering::Relaxed);
            stats.bytes.store(local_bytes, Ordering::Relaxed);
            stats.recv_errors.store(local_errs, Ordering::Relaxed);
            since_flush = 0;
        }
    }

    // Final publish so the status logger sees the terminal counts.
    stats.packets.store(local_pkts, Ordering::Relaxed);
    stats.bytes.store(local_bytes, Ordering::Relaxed);
    stats.recv_errors.store(local_errs, Ordering::Relaxed);
    debug!("shred receiver thread exiting");
}
