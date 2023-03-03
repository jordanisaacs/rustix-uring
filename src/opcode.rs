//! Operation codes that can be used to construct [`squeue::Entry`](crate::squeue::Entry)s.

#![allow(clippy::new_without_default)]

use core::convert::TryInto;
use core::mem;

use crate::squeue::Entry;
use crate::squeue::Entry128;

use libc::epoll_event;
use rustix::io_uring;

use crate::types::{
    sealed, AcceptFlags, Advice, AtFlags, DestinationSlot, Fixed, IoringAcceptFlags,
    IoringAsyncCancelFlags, IoringFsyncFlags, IoringMsgringCmds, IoringMsgringFlags, IoringOp,
    IoringPollFlags, IoringRecvFlags, IoringSendFlags, IoringSqeFlags, IoringTimeoutFlags,
    IoringUserData, OFlags, OpenHow, RawFd, ReadWriteFlags, RecvFlags, RenameFlags, SendFlags,
    SpliceFlags, Timespec,
};

macro_rules! assign_fd {
    ( $sqe:ident . fd = $opfd:expr ) => {
        match $opfd {
            sealed::Target::Fd(fd) => $sqe.fd = fd,
            sealed::Target::Fixed(i) => {
                $sqe.fd = i as _;
                $sqe.flags |= IoringSqeFlags::FIXED_FILE;
            }
        }
    };
}

macro_rules! opcode {

    (@type impl sealed::UseFixed ) => {
        sealed::Target
    };
    (@type impl sealed::UseFd ) => {
        RawFd
    };
    (@type $name:ty ) => {
        $name
    };
    (
        $( #[$outer:meta] )*
        pub struct $name:ident {
            $( #[$new_meta:meta] )*

            $( $field:ident : { $( $tnt:tt )+ } ),*

            $(,)?

            ;;

            $(
                $( #[$opt_meta:meta] )*
                $opt_field:ident : $opt_tname:ty = $default:expr
            ),*

            $(,)?
        }

        pub const CODE = $opcode:expr;

        $( #[$build_meta:meta] )*
        pub fn build($self:ident) -> $entry:ty $build_block:block
    ) => {
        $( #[$outer] )*
        pub struct $name {
            $( $field : opcode!(@type $( $tnt )*), )*
            $( $opt_field : $opt_tname, )*
        }

        #[allow(deprecated)]
        impl $name {
            $( #[$new_meta] )*
            #[inline]
            pub fn new($( $field : $( $tnt )* ),*) -> Self {
                $name {
                    $( $field: $field.into(), )*
                    $( $opt_field: $default, )*
                }
            }

            /// The opcode of the operation. This can be passed to
            /// [`Probe::is_supported`](crate::Probe::is_supported) to check if this operation is
            /// supported with the current kernel.
            pub const CODE: IoringOp = $opcode as _;

            $(
                $( #[$opt_meta] )*
                #[inline]
                pub const fn $opt_field(mut self, $opt_field: $opt_tname) -> Self {
                    self.$opt_field = $opt_field;
                    self
                }
            )*

            $( #[$build_meta] )*
            #[inline]
            pub fn build($self) -> $entry $build_block
        }
    }
}

/// inline zeroed to improve codegen
#[inline(always)]
fn sqe_zeroed() -> io_uring::io_uring_sqe {
    io_uring::io_uring_sqe::default()
}

/// Cast pointer to io_uring_ptr
#[inline(always)]
fn to_iouring_ptr<T>(f: *mut T) -> io_uring::io_uring_ptr {
    io_uring::io_uring_ptr::from(f.cast())
}

opcode!(
    /// Do not perform any I/O.
    ///
    /// This is useful for testing the performance of the io_uring implementation itself.
    #[derive(Debug)]
    pub struct Nop { ;; }

    pub const CODE = IoringOp::Nop;

    pub fn build(self) -> Entry {
        let Nop {} = self;

        let mut sqe = sqe_zeroed();
        sqe.opcode = Self::CODE;
        sqe.fd = -1;
        Entry(sqe)
    }
);

opcode!(
    /// Vectored read, equivalent to `preadv2(2)`.
    #[derive(Debug)]
    pub struct Readv {
        fd: { impl sealed::UseFixed },
        iovec: { *const libc::iovec },
        len: { u32 },
        ;;
        ioprio: u16 = 0,
        offset64: u64 = 0,
        /// specified for read operations, contains a bitwise OR of per-I/O flags,
        /// as described in the `preadv2(2)` man page.
        rw_flags: ReadWriteFlags = ReadWriteFlags::empty(),
        buf_group: u16 = 0
    }

    pub const CODE = IoringOp::Readv;

    pub fn build(self) -> Entry {
        let Readv {
            fd,
            iovec, len, offset64,
            ioprio, rw_flags,
            buf_group
        } = self;

        let mut sqe = sqe_zeroed();
        sqe.opcode = Self::CODE;
        assign_fd!(sqe.fd = fd);
        sqe.ioprio.ioprio = ioprio;
        sqe.addr_or_splice_off_in.addr = to_iouring_ptr(iovec.cast_mut());
        sqe.len.len = len;
        sqe.off_or_addr2.off = offset64;
        sqe.op_flags.rw_flags = rw_flags;
        sqe.buf.buf_group = buf_group;
        Entry(sqe)
    }
);

impl Readv {
    #[inline]
    pub const fn offset(self, offset: u64) -> Self {
        self.offset64(offset)
    }
}

opcode!(
    /// Vectored write, equivalent to `pwritev2(2)`.
    #[derive(Debug)]
    pub struct Writev {
        fd: { impl sealed::UseFixed },
        iovec: { *const libc::iovec },
        len: { u32 },
        ;;
        ioprio: u16 = 0,
        offset64: u64 = 0,
        /// specified for write operations, contains a bitwise OR of per-I/O flags,
        /// as described in the `preadv2(2)` man page.
        rw_flags: ReadWriteFlags = ReadWriteFlags::empty()
    }

    pub const CODE = IoringOp::Writev;

    pub fn build(self) -> Entry {
        let Writev {
            fd,
            iovec, len, offset64,
            ioprio, rw_flags
        } = self;

        let mut sqe = sqe_zeroed();
        sqe.opcode = Self::CODE;
        assign_fd!(sqe.fd = fd);
        sqe.ioprio.ioprio = ioprio;
        sqe.addr_or_splice_off_in.addr = to_iouring_ptr(iovec.cast_mut());
        sqe.len.len = len;
        sqe.off_or_addr2.off = offset64;
        sqe.op_flags.rw_flags = rw_flags;
        Entry(sqe)
    }
);

impl Writev {
    #[inline]
    pub const fn offset(self, offset: u64) -> Self {
        self.offset64(offset)
    }
}

opcode!(
    /// File sync, equivalent to `fsync(2)`.
    ///
    /// Note that, while I/O is initiated in the order in which it appears in the submission queue,
    /// completions are unordered. For example, an application which places a write I/O followed by
    /// an fsync in the submission queue cannot expect the fsync to apply to the write. The two
    /// operations execute in parallel, so the fsync may complete before the write is issued to the
    /// storage. The same is also true for previously issued writes that have not completed prior to
    /// the fsync.
    #[derive(Debug)]
    pub struct Fsync {
        fd: { impl sealed::UseFixed },
        ;;
        /// The `flags` bit mask may contain either 0, for a normal file integrity sync,
        /// or [crate::types::IoringFsyncFlags::DATASYNC] to provide data sync only semantics.
        /// See the descriptions of `O_SYNC` and `O_DSYNC` in the `open(2)` manual page for more information.
        flags: IoringFsyncFlags = IoringFsyncFlags::empty()
    }

    pub const CODE = IoringOp::Fsync;

    pub fn build(self) -> Entry {
        let Fsync { fd, flags } = self;

        let mut sqe = sqe_zeroed();
        sqe.opcode = Self::CODE;
        assign_fd!(sqe.fd = fd);
        sqe.op_flags.fsync_flags = flags;
        Entry(sqe)
    }
);

opcode!(
    /// Read from pre-mapped buffers that have been previously registered with
    /// [`Submitter::register_buffers`](crate::Submitter::register_buffers).
    ///
    /// The return values match those documented in the `preadv2(2)` man pages.
    #[derive(Debug)]
    pub struct ReadFixed {
        /// The `buf_index` is an index into an array of fixed buffers,
        /// and is only valid if fixed buffers were registered.
        fd: { impl sealed::UseFixed },
        buf: { *mut u8 },
        len: { u32 },
        buf_index: { u16 },
        ;;
        offset64: u64 = 0,
        ioprio: u16 = 0,
        /// specified for read operations, contains a bitwise OR of per-I/O flags,
        /// as described in the `preadv2(2)` man page.
        rw_flags: ReadWriteFlags = ReadWriteFlags::empty()
    }

    pub const CODE = IoringOp::ReadFixed;

    pub fn build(self) -> Entry {
        let ReadFixed {
            fd,
            buf, len, offset64,
            buf_index,
            ioprio, rw_flags
        } = self;

        let mut sqe = sqe_zeroed();
        sqe.opcode = Self::CODE;
        assign_fd!(sqe.fd = fd);
        sqe.ioprio.ioprio = ioprio;
        sqe.addr_or_splice_off_in.addr = to_iouring_ptr(buf);
        sqe.len.len = len;
        sqe.off_or_addr2.off = offset64;
        sqe.op_flags.rw_flags = rw_flags;
        sqe.buf.buf_index = buf_index;
        Entry(sqe)
    }
);

impl ReadFixed {
    #[inline]
    pub const fn offset(self, offset: u64) -> Self {
        self.offset64(offset)
    }
}

opcode!(
    /// Write to pre-mapped buffers that have been previously registered with
    /// [`Submitter::register_buffers`](crate::Submitter::register_buffers).
    ///
    /// The return values match those documented in the `pwritev2(2)` man pages.
    #[derive(Debug)]
    pub struct WriteFixed {
        /// The `buf_index` is an index into an array of fixed buffers,
        /// and is only valid if fixed buffers were registered.
        fd: { impl sealed::UseFixed },
        buf: { *const u8 },
        len: { u32 },
        buf_index: { u16 },
        ;;
        ioprio: u16 = 0,
        offset64: u64 = 0,
        /// specified for write operations, contains a bitwise OR of per-I/O flags,
        /// as described in the `preadv2(2)` man page.
        rw_flags: ReadWriteFlags = ReadWriteFlags::empty()
    }

    pub const CODE = IoringOp::WriteFixed;

    pub fn build(self) -> Entry {
        let WriteFixed {
            fd,
            buf, len, offset64,
            buf_index,
            ioprio, rw_flags
        } = self;

        let mut sqe = sqe_zeroed();
        sqe.opcode = Self::CODE;
        assign_fd!(sqe.fd = fd);
        sqe.ioprio.ioprio = ioprio;
        sqe.addr_or_splice_off_in.addr = to_iouring_ptr(buf.cast_mut());
        sqe.len.len = len;
        sqe.off_or_addr2.off = offset64;
        sqe.op_flags.rw_flags = rw_flags;
        sqe.buf.buf_index = buf_index;
        Entry(sqe)
    }
);

impl WriteFixed {
    #[inline]
    pub const fn offset(self, offset: u64) -> Self {
        self.offset64(offset)
    }
}

opcode!(
    /// Poll the specified fd.
    ///
    /// Unlike poll or epoll without `EPOLLONESHOT`, this interface defaults to work in one shot mode.
    /// That is, once the poll operation is completed, it will have to be resubmitted.
    ///
    /// If multi is set, the poll will work in multi shot mode instead. That means it will
    /// repeatedly trigger when the requested event becomes true, and hence multiple CQEs can be
    /// generated from this single submission. The CQE flags field will have IORING_CQE_F_MORE set
    /// on completion if the application should expect further CQE entries from the original
    /// request. If this flag isn't set on completion, then the poll request has been terminated
    /// and no further events will be generated. This mode is available since 5.13.
    #[derive(Debug)]
    pub struct PollAdd {
        /// The bits that may be set in `flags` are defined in `<poll.h>`,
        /// and documented in `poll(2)`.
        fd: { impl sealed::UseFixed },
        flags: { u32 },
        ;;
        multi: bool = false
    }

    pub const CODE = IoringOp::PollAdd;

    pub fn build(self) -> Entry {
        let PollAdd { fd, flags, multi } = self;

        let mut sqe = sqe_zeroed();
        sqe.opcode = Self::CODE;
        assign_fd!(sqe.fd = fd);
        if multi {
            sqe.len.poll_flags = IoringPollFlags::ADD_MULTI;
        }



        #[cfg(target_endian = "little")] {
            sqe.op_flags.poll32_events = flags;
        }

        #[cfg(target_endian = "big")] {
            let x = flags << 16;
            let y = flags >> 16;
            let flags = x | y;
            sqe.op_flags.poll32_events = flags;
        }

        Entry(sqe)
    }
);

opcode!(
    /// Remove an existing [poll](PollAdd) request.
    ///
    /// If found, the `result` method of the `cqueue::Entry` will return 0.
    /// If not found, `result` will return `-libc::ENOENT`.
    // TODO: #[derive(Debug)] for io_uring_ptr
    pub struct PollRemove {
        user_data: { IoringUserData }
        ;;
    }

    pub const CODE = IoringOp::PollRemove;

    pub fn build(self) -> Entry {
        let PollRemove { user_data } = self;

        let mut sqe = sqe_zeroed();
        sqe.opcode = Self::CODE;
        sqe.fd = -1;
        sqe.addr_or_splice_off_in.user_data = user_data;
        Entry(sqe)
    }
);

opcode!(
    /// Sync a file segment with disk, equivalent to `sync_file_range(2)`.
    #[derive(Debug)]
    pub struct SyncFileRange {
        fd: { impl sealed::UseFixed },
        len: { u32 },
        ;;
        /// the offset method holds the offset in bytes
        offset: u64 = 0,
        /// the flags method holds the flags for the command
        flags: u32 = 0
    }

    pub const CODE = IoringOp::SyncFileRange;

    pub fn build(self) -> Entry {
        let SyncFileRange {
            fd,
            len, offset,
            flags
        } = self;

        let mut sqe = sqe_zeroed();
        sqe.opcode = Self::CODE;
        assign_fd!(sqe.fd = fd);
        sqe.len.len = len as _;
        sqe.off_or_addr2.off = offset;
        sqe.op_flags.sync_range_flags = flags;
        Entry(sqe)
    }
);

opcode!(
    /// Send a message on a socket, equivalent to `send(2)`.
    ///
    /// fd must be set to the socket file descriptor, addr must contains a pointer to the msghdr
    /// structure, and flags holds the flags associated with the system call.
    #[derive(Debug)]
    pub struct SendMsg {
        fd: { impl sealed::UseFixed },
        msg: { *const libc::msghdr },
        ;;
        ioprio: u16 = 0,
        flags: SendFlags = SendFlags::empty()
    }

    pub const CODE = IoringOp::Sendmsg;

    pub fn build(self) -> Entry {
        let SendMsg { fd, msg, ioprio, flags } = self;

        let mut sqe = sqe_zeroed();
        sqe.opcode = Self::CODE;
        assign_fd!(sqe.fd = fd);
        sqe.ioprio.ioprio = ioprio;
        sqe.addr_or_splice_off_in.addr = to_iouring_ptr(msg.cast_mut());
        sqe.len.len = 1;
        sqe.op_flags.send_flags = flags;
        Entry(sqe)
    }
);

fn recvmsg_zeroed() -> RecvFlags {
    unsafe { core::mem::zeroed() }
}

opcode!(
    /// Receive a message on a socket, equivalent to `recvmsg(2)`.
    ///
    /// See also the description of [`SendMsg`].
    #[derive(Debug)]
    pub struct RecvMsg {
        fd: { impl sealed::UseFixed },
        msg: { *mut libc::msghdr },
        ;;
        ioprio: u16 = 0,
        flags: RecvFlags = recvmsg_zeroed(),
        buf_group: u16 = 0
    }

    pub const CODE = IoringOp::Recvmsg;

    pub fn build(self) -> Entry {
        let RecvMsg { fd, msg, ioprio, flags, buf_group } = self;

        let mut sqe = sqe_zeroed();
        sqe.opcode = Self::CODE;
        assign_fd!(sqe.fd = fd);
        sqe.ioprio.ioprio = ioprio;
        sqe.addr_or_splice_off_in.addr = to_iouring_ptr(msg);
        sqe.len.len = 1;
        sqe.op_flags.recv_flags = flags;
        sqe.buf.buf_group = buf_group;
        Entry(sqe)
    }
);

opcode!(
    /// Receive multiple messages on a socket, equivalent to `recvmsg(2)`.
    ///
    /// Parameters:
    ///     msg:       For this multishot variant of ResvMsg, only the msg_namelen and msg_controllen
    ///                fields are relevant.
    ///     buf_group: The id of the provided buffer pool to use for each received message.
    ///
    /// See also the description of [`SendMsg`] and [`crate::types::RecvMsgOut`].
    ///
    /// The multishot version allows the application to issue a single receive request, which
    /// repeatedly posts a CQE when data is available. It requires the MSG_WAITALL flag is not set.
    /// Each CQE will take a buffer out of a provided buffer pool for receiving. The application
    /// should check the flags of each CQE, regardless of its result. If a posted CQE does not have
    /// the IORING_CQE_F_MORE flag set then the multishot receive will be done and the application
    /// should issue a new request.
    ///
    /// Unlike [`RecvMsg`], this multishot recvmsg will prepend a struct which describes the layout
    /// of the rest of the buffer in combination with the initial msghdr structure submitted with
    /// the request. Use [`crate::types::RecvMsgOut`] to parse the data received and access its
    /// components.
    ///
    /// The recvmsg multishot variant is available since kernel 6.0.

    #[derive(Debug)]
    pub struct RecvMsgMulti {
        fd: { impl sealed::UseFixed },
        msg: { *const libc::msghdr },
        buf_group: { u16 },
        ;;
        ioprio: IoringRecvFlags = IoringRecvFlags::empty(),
        flags: RecvFlags = RecvFlags::empty()
    }

    pub const CODE = IoringOp::Recvmsg;

    pub fn build(self) -> Entry {
        let RecvMsgMulti { fd, msg, buf_group, ioprio, flags } = self;

        let mut sqe = sqe_zeroed();
        sqe.opcode = Self::CODE;
        assign_fd!(sqe.fd = fd);
        sqe.addr_or_splice_off_in.addr = to_iouring_ptr(msg.cast_mut());
        sqe.len.len = 1;
        sqe.op_flags.recv_flags = flags;
        sqe.buf.buf_group = buf_group;
        sqe.flags |= IoringSqeFlags::BUFFER_SELECT;
        sqe.ioprio.recv_flags = ioprio | IoringRecvFlags::MULTISHOT;
        Entry(sqe)
    }
);

opcode!(
    /// Register a timeout operation.
    ///
    /// A timeout will trigger a wakeup event on the completion ring for anyone waiting for events.
    /// A timeout condition is met when either the specified timeout expires, or the specified number of events have completed.
    /// Either condition will trigger the event.
    /// The request will complete with `-ETIME` if the timeout got completed through expiration of the timer,
    /// or 0 if the timeout got completed through requests completing on their own.
    /// If the timeout was cancelled before it expired, the request will complete with `-ECANCELED`.
    #[derive(Debug)]
    pub struct Timeout {
        timespec: { *const Timespec },
        ;;
        /// `count` may contain a completion event count.
        count: u32 = 0,

        /// `flags` may contain [crate::types::IoringTimeoutFlags::ABS] for an absolute timeout value, or 0 for a relative timeout.
        flags: IoringTimeoutFlags = IoringTimeoutFlags::empty()
    }

    pub const CODE = IoringOp::Timeout;

    pub fn build(self) -> Entry {
        let Timeout { timespec, count, flags } = self;

        let mut sqe = sqe_zeroed();
        sqe.opcode = Self::CODE;
        sqe.fd = -1;
        sqe.addr_or_splice_off_in.addr = to_iouring_ptr(timespec.cast_mut());
        sqe.len.len = 1;
        sqe.off_or_addr2.off = count as _;
        sqe.op_flags.timeout_flags = flags;
        Entry(sqe)
    }
);

// === 5.5 ===

opcode!(
    /// Attempt to remove an existing [timeout operation](Timeout).
    pub struct TimeoutRemove {
        user_data: { IoringUserData }
        ;;
        flags: IoringTimeoutFlags = IoringTimeoutFlags::empty()
    }

    pub const CODE = IoringOp::TimeoutRemove;

    pub fn build(self) -> Entry {
        let TimeoutRemove { user_data, flags } = self;

        let mut sqe = sqe_zeroed();
        sqe.opcode = Self::CODE;
        sqe.fd = -1;
        sqe.addr_or_splice_off_in.user_data = user_data;
        sqe.op_flags.timeout_flags = flags;
        Entry(sqe)
    }
);

opcode!(
    /// Accept a new connection on a socket, equivalent to `accept4(2)`.
    pub struct Accept {
        fd: { impl sealed::UseFixed },
        addr: { *mut libc::sockaddr },
        addrlen: { *mut libc::socklen_t },
        ;;
        file_index: Option<DestinationSlot> = None,
        flags: AcceptFlags = AcceptFlags::empty()
    }

    pub const CODE = IoringOp::Accept;

    pub fn build(self) -> Entry {
        let Accept { fd, addr, addrlen, file_index, flags } = self;

        let mut sqe = sqe_zeroed();
        sqe.opcode = Self::CODE;
        assign_fd!(sqe.fd = fd);
        sqe.addr_or_splice_off_in.addr = to_iouring_ptr(addr);
        sqe.off_or_addr2.addr2 = to_iouring_ptr(addrlen);
        sqe.op_flags.accept_flags = flags;
        if let Some(dest) = file_index {
            sqe.splice_fd_in_or_file_index.file_index = dest.kernel_index_arg();
        }
        Entry(sqe)
    }
);

opcode!(
    /// Accept multiple new connections on a socket.
    ///
    /// Set the `allocate_file_index` property if fixed file table entries should be used.
    pub struct AcceptMulti {
        fd: { impl sealed::UseFixed },
        ;;
        allocate_file_index: bool = false,
        flags: AcceptFlags = AcceptFlags::empty()
    }

    pub const CODE = IoringOp::Accept;

    pub fn build(self) -> Entry {
        let AcceptMulti { fd, allocate_file_index, flags } = self;

        let mut sqe = sqe_zeroed();
        sqe.opcode = Self::CODE;
        assign_fd!(sqe.fd = fd);
        sqe.ioprio.accept_flags = IoringAcceptFlags::MULTISHOT;
        // No out SockAddr is passed for the multishot accept case.
        // The user should perform a syscall to get any resulting connection's remote address.
        sqe.op_flags.accept_flags = flags;
        if allocate_file_index {
            sqe.splice_fd_in_or_file_index.file_index = io_uring::IORING_FILE_INDEX_ALLOC as u32;
        }
        Entry(sqe)
    }
);

opcode!(
    /// Attempt to cancel an already issued request.
    pub struct AsyncCancel {
        user_data: { IoringUserData }
        ;;

        flags: IoringAsyncCancelFlags = IoringAsyncCancelFlags::empty(),
    }

    pub const CODE = IoringOp::AsyncCancel;

    pub fn build(self) -> Entry {
        let AsyncCancel { user_data, flags } = self;

        let mut sqe = sqe_zeroed();
        sqe.opcode = Self::CODE;
        sqe.fd = -1;
        sqe.op_flags.cancel_flags = flags;
        sqe.addr_or_splice_off_in.user_data = user_data;
        Entry(sqe)
    }
);

opcode!(
    /// This request must be linked with another request through
    /// [`Flags::IO_LINK`](crate::types::IoringSqeFlags::IO_LINK) which is described below.
    /// Unlike [`Timeout`], [`LinkTimeout`] acts on the linked request, not the completion queue.
    pub struct LinkTimeout {
        timespec: { *const Timespec },
        ;;
        flags: IoringTimeoutFlags = IoringTimeoutFlags::empty()
    }

    pub const CODE = IoringOp::LinkTimeout;

    pub fn build(self) -> Entry {
        let LinkTimeout { timespec, flags } = self;

        let mut sqe = sqe_zeroed();
        sqe.opcode = Self::CODE;
        sqe.fd = -1;
        sqe.addr_or_splice_off_in.addr = to_iouring_ptr(timespec.cast_mut());
        sqe.len.len = 1;
        sqe.op_flags.timeout_flags = flags;
        Entry(sqe)
    }
);

opcode!(
    /// Connect a socket, equivalent to `connect(2)`.
    pub struct Connect {
        fd: { impl sealed::UseFixed },
        addr: { *const libc::sockaddr },
        addrlen: { libc::socklen_t }
        ;;
    }

    pub const CODE = IoringOp::Connect;

    pub fn build(self) -> Entry {
        let Connect { fd, addr, addrlen } = self;

        let mut sqe = sqe_zeroed();
        sqe.opcode = Self::CODE;
        assign_fd!(sqe.fd = fd);
        sqe.addr_or_splice_off_in.addr = to_iouring_ptr(addr.cast_mut());
        sqe.off_or_addr2.off = addrlen as _;
        Entry(sqe)
    }
);

// === 5.6 ===

opcode!(
    /// Preallocate or deallocate space to a file, equivalent to `fallocate(2)`.
    #[deprecated(note = "use Fallocate64 instead, which always takes a 64-bit length")]
    pub struct Fallocate {
        fd: { impl sealed::UseFixed },
        len: { u64 },
        ;;
        offset64: u64 = 0,
        mode: i32 = 0
    }

    pub const CODE = IoringOp::Fallocate;

    pub fn build(self) -> Entry {
        let Fallocate { fd, len, offset64, mode } = self;

        let mut sqe = sqe_zeroed();
        sqe.opcode = Self::CODE;
        assign_fd!(sqe.fd = fd);
        sqe.addr_or_splice_off_in.splice_off_in = len;
        sqe.len.len = mode as _;
        sqe.off_or_addr2.off = offset64;
        Entry(sqe)
    }
);

#[allow(deprecated)]
impl Fallocate {
    #[inline]
    pub const fn offset(self, offset: u64) -> Self {
        self.offset64(offset)
    }
}

opcode!(
    /// Preallocate or deallocate space to a file, equivalent to `fallocate(2)`.
    pub struct Fallocate64 {
        fd: { impl sealed::UseFixed },
        len: { libc::off64_t },
        ;;
        offset64: u64 = 0,
        mode: i32 = 0
    }

    pub const CODE = IoringOp::Fallocate;

    pub fn build(self) -> Entry {
        let Fallocate64 { fd, len, offset64, mode } = self;

        let mut sqe = sqe_zeroed();
        sqe.opcode = Self::CODE;
        assign_fd!(sqe.fd = fd);
        // TODO: not really splice_off_in
        sqe.addr_or_splice_off_in.splice_off_in = len as _;
        sqe.len.len = mode as _;
        sqe.off_or_addr2.off = offset64;
        Entry(sqe)
    }
);

impl Fallocate64 {
    #[inline]
    pub const fn offset(self, offset: u64) -> Self {
        self.offset64(offset)
    }
}

opcode!(
    /// Open a file, equivalent to `openat(2)`.
    pub struct OpenAt {
        dirfd: { impl sealed::UseFd },
        pathname: { *const libc::c_char },
        ;;
        file_index: Option<DestinationSlot> = None,
        flags: OFlags = OFlags::empty(),
        mode: libc::mode_t = 0
    }

    pub const CODE = IoringOp::Openat;

    pub fn build(self) -> Entry {
        let OpenAt { dirfd, pathname, file_index, flags, mode } = self;

        let mut sqe = sqe_zeroed();
        sqe.opcode = Self::CODE;
        sqe.fd = dirfd;
        sqe.addr_or_splice_off_in.addr = to_iouring_ptr(pathname.cast_mut());
        sqe.len.len = mode;
        sqe.op_flags.open_flags = flags;
        if let Some(dest) = file_index {
            sqe.splice_fd_in_or_file_index.file_index = dest.kernel_index_arg();
        }
        Entry(sqe)
    }
);

opcode!(
    /// Close a file descriptor, equivalent to `close(2)`.
    ///
    /// Use a types::Fixed(fd) argument to close an io_uring direct descriptor.
    pub struct Close {
        fd: { impl sealed::UseFixed },
        ;;
    }

    pub const CODE = IoringOp::Close;

    pub fn build(self) -> Entry {
        let Close { fd } = self;

        let mut sqe = sqe_zeroed();
        sqe.opcode = Self::CODE;
        match fd {
            sealed::Target::Fd(i) => sqe.fd = i,
            sealed::Target::Fixed(i) => {
                sqe.fd = 0;
                sqe.splice_fd_in_or_file_index.file_index = i+1;
            }
        }
        Entry(sqe)
    }
);

opcode!(
    /// This command is an alternative to using
    /// [`Submitter::register_files_update`](crate::Submitter::register_files_update) which then
    /// works in an async fashion, like the rest of the io_uring commands.
    pub struct FilesUpdate {
        fds: { *const RawFd },
        len: { u32 },
        ;;
        offset: i32 = 0
    }

    pub const CODE = IoringOp::FilesUpdate;

    pub fn build(self) -> Entry {
        let FilesUpdate { fds, len, offset } = self;

        let mut sqe = sqe_zeroed();
        sqe.opcode = Self::CODE;
        sqe.fd = -1;
        sqe.addr_or_splice_off_in.addr = to_iouring_ptr(fds.cast_mut());
        sqe.len.len = len;
        sqe.off_or_addr2.off = offset as _;
        Entry(sqe)
    }
);

opcode!(
    /// Get file status, equivalent to `statx(2)`.
    pub struct Statx {
        dirfd: { impl sealed::UseFd },
        pathname: { *const libc::c_char },
        statxbuf: { *mut Statx },
        ;;
        flags: AtFlags = AtFlags::empty(),
        mask: u32 = 0
    }

    pub const CODE = IoringOp::Statx;

    pub fn build(self) -> Entry {
        let Statx {
            dirfd, pathname, statxbuf,
            flags, mask
        } = self;

        let mut sqe = sqe_zeroed();
        sqe.opcode = Self::CODE;
        sqe.fd = dirfd;
        sqe.addr_or_splice_off_in.addr = to_iouring_ptr(pathname.cast_mut());
        sqe.len.len = mask;
        sqe.off_or_addr2.off = statxbuf as _;
        sqe.op_flags.statx_flags = flags;
        Entry(sqe)
    }
);

opcode!(
    /// Issue the equivalent of a `pread(2)` or `pwrite(2)` system call
    ///
    /// * `fd` is the file descriptor to be operated on,
    /// * `addr` contains the buffer in question,
    /// * `len` contains the length of the IO operation,
    ///
    /// These are non-vectored versions of the `IORING_OP_READV` and `IORING_OP_WRITEV` opcodes.
    /// See also `read(2)` and `write(2)` for the general description of the related system call.
    ///
    /// Available since 5.6.
    pub struct Read {
        fd: { impl sealed::UseFixed },
        buf: { *mut u8 },
        len: { u32 },
        ;;
        /// `offset` contains the read or write offset.
        ///
        /// If `fd` does not refer to a seekable file, `offset` must be set to zero.
        /// If `offsett` is set to `-1`, the offset will use (and advance) the file position,
        /// like the `read(2)` and `write(2)` system calls.
        offset64: u64 = 0,
        ioprio: u16 = 0,
        rw_flags: ReadWriteFlags = ReadWriteFlags::empty(),
        buf_group: u16 = 0
    }

    pub const CODE = IoringOp::Read;

    pub fn build(self) -> Entry {
        let Read {
            fd,
            buf, len, offset64,
            ioprio, rw_flags,
            buf_group
        } = self;

        let mut sqe = sqe_zeroed();
        sqe.opcode = Self::CODE;
        assign_fd!(sqe.fd = fd);
        sqe.ioprio.ioprio = ioprio;
        sqe.addr_or_splice_off_in.addr = to_iouring_ptr(buf);
        sqe.len.len = len;
        sqe.off_or_addr2.off = offset64;
        sqe.op_flags.rw_flags = rw_flags;
        sqe.buf.buf_group = buf_group;
        Entry(sqe)
    }
);

impl Read {
    #[inline]
    pub const fn offset(self, offset: u64) -> Self {
        self.offset64(offset)
    }
}

opcode!(
    /// Issue the equivalent of a `pread(2)` or `pwrite(2)` system call
    ///
    /// * `fd` is the file descriptor to be operated on,
    /// * `addr` contains the buffer in question,
    /// * `len` contains the length of the IO operation,
    ///
    /// These are non-vectored versions of the `IORING_OP_READV` and `IORING_OP_WRITEV` opcodes.
    /// See also `read(2)` and `write(2)` for the general description of the related system call.
    ///
    /// Available since 5.6.
    pub struct Write {
        fd: { impl sealed::UseFixed },
        buf: { *const u8 },
        len: { u32 },
        ;;
        /// `offset` contains the read or write offset.
        ///
        /// If `fd` does not refer to a seekable file, `offset` must be set to zero.
        /// If `offsett` is set to `-1`, the offset will use (and advance) the file position,
        /// like the `read(2)` and `write(2)` system calls.
        offset64: u64 = 0,
        ioprio: u16 = 0,
        rw_flags: ReadWriteFlags = ReadWriteFlags::empty()
    }

    pub const CODE = IoringOp::Write;

    pub fn build(self) -> Entry {
        let Write {
            fd,
            buf, len, offset64,
            ioprio, rw_flags
        } = self;

        let mut sqe = sqe_zeroed();
        sqe.opcode = Self::CODE;
        assign_fd!(sqe.fd = fd);
        sqe.ioprio.ioprio = ioprio;
        sqe.addr_or_splice_off_in.addr = to_iouring_ptr(buf.cast_mut());
        sqe.len.len = len;
        sqe.off_or_addr2.off = offset64;
        sqe.op_flags.rw_flags = rw_flags;
        Entry(sqe)
    }
);

impl Write {
    #[inline]
    pub const fn offset(self, offset: u64) -> Self {
        self.offset64(offset)
    }
}

opcode!(
    /// Predeclare an access pattern for file data, equivalent to `posix_fadvise(2)`.
    pub struct Fadvise {
        fd: { impl sealed::UseFixed },
        len: { libc::off_t },
        advice: { Advice },
        ;;
        offset64: u64 = 0,
    }

    pub const CODE = IoringOp::Fadvise;

    pub fn build(self) -> Entry {
        let Fadvise { fd, len, advice, offset64 } = self;

        let mut sqe = sqe_zeroed();
        sqe.opcode = Self::CODE;
        assign_fd!(sqe.fd = fd);
        sqe.len.len = len as _;
        sqe.off_or_addr2.off = offset64;
        sqe.op_flags.fadvise_advice = advice;
        Entry(sqe)
    }
);

impl Fadvise {
    #[inline]
    pub const fn offset(self, offset: u64) -> Self {
        self.offset64(offset)
    }
}

opcode!(
    /// Give advice about use of memory, equivalent to `madvise(2)`.
    pub struct Madvise {
        addr: { *const libc::c_void },
        len: { libc::off_t },
        advice: { Advice },
        ;;
    }

    pub const CODE = IoringOp::Madvise;

    pub fn build(self) -> Entry {
        let Madvise { addr, len, advice } = self;

        let mut sqe = sqe_zeroed();
        sqe.opcode = Self::CODE;
        sqe.fd = -1;
        sqe.addr_or_splice_off_in.addr = to_iouring_ptr(addr.cast_mut());
        sqe.len.len = len as _;
        sqe.op_flags.fadvise_advice = advice;
        Entry(sqe)
    }
);

opcode!(
    /// Send a message on a socket, equivalent to `send(2)`.
    pub struct Send {
        fd: { impl sealed::UseFixed },
        buf: { *const u8 },
        len: { u32 },
        ;;
        flags: SendFlags = SendFlags::empty()
    }

    pub const CODE = IoringOp::Send;

    pub fn build(self) -> Entry {
        let Send { fd, buf, len, flags } = self;

        let mut sqe = sqe_zeroed();
        sqe.opcode = Self::CODE;
        assign_fd!(sqe.fd = fd);
        sqe.addr_or_splice_off_in.addr = to_iouring_ptr(buf.cast_mut());
        sqe.len.len = len;
        sqe.op_flags.send_flags = flags;
        Entry(sqe)
    }
);

opcode!(
    /// Receive a message from a socket, equivalent to `recv(2)`.
    pub struct Recv {
        fd: { impl sealed::UseFixed },
        buf: { *mut u8 },
        len: { u32 },
        ;;
        flags: RecvFlags = RecvFlags::empty(),
        buf_group: u16 = 0
    }

    pub const CODE = IoringOp::Recv;

    pub fn build(self) -> Entry {
        let Recv { fd, buf, len, flags, buf_group } = self;

        let mut sqe = sqe_zeroed();
        sqe.opcode = Self::CODE;
        assign_fd!(sqe.fd = fd);
        sqe.addr_or_splice_off_in.addr = to_iouring_ptr(buf);
        sqe.len.len = len;
        sqe.op_flags.recv_flags = flags;
        sqe.buf.buf_group = buf_group;
        Entry(sqe)
    }
);

opcode!(
    /// Receive multiple messages from a socket, equivalent to `recv(2)`.
    ///
    /// Parameter:
    ///     buf_group: The id of the provided buffer pool to use for each received message.
    ///
    /// MSG_WAITALL should not be set in flags.
    ///
    /// The multishot version allows the application to issue a single receive request, which
    /// repeatedly posts a CQE when data is available. Each CQE will take a buffer out of a
    /// provided buffer pool for receiving. The application should check the flags of each CQE,
    /// regardless of its result. If a posted CQE does not have the IORING_CQE_F_MORE flag set then
    /// the multishot receive will be done and the application should issue a new request.
    ///
    /// Multishot variants are available since kernel 6.0.

    pub struct RecvMulti {
        fd: { impl sealed::UseFixed },
        buf_group: { u16 },
        ;;
        flags: RecvFlags = RecvFlags::empty(),
    }

    pub const CODE = IoringOp::Recv;

    pub fn build(self) -> Entry {
        let RecvMulti { fd, buf_group, flags } = self;

        let mut sqe = sqe_zeroed();
        sqe.opcode = Self::CODE;
        assign_fd!(sqe.fd = fd);
        sqe.op_flags.recv_flags = flags;
        sqe.buf.buf_group = buf_group;
        sqe.flags |= IoringSqeFlags::BUFFER_SELECT;
        sqe.ioprio.recv_flags = IoringRecvFlags::MULTISHOT;
        Entry(sqe)
    }
);

opcode!(
    /// Open a file, equivalent to `openat2(2)`.
    pub struct OpenAt2 {
        dirfd: { impl sealed::UseFd },
        pathname: { *const libc::c_char },
        how: { *const OpenHow }
        ;;
        file_index: Option<DestinationSlot> = None,
    }

    pub const CODE = IoringOp::Openat2;

    pub fn build(self) -> Entry {
        let OpenAt2 { dirfd, pathname, how, file_index } = self;

        let mut sqe = sqe_zeroed();
        sqe.opcode = Self::CODE;
        sqe.fd = dirfd;
        sqe.addr_or_splice_off_in.addr = to_iouring_ptr(pathname.cast_mut());
        sqe.len.len = mem::size_of::<io_uring::open_how>() as _;
        sqe.off_or_addr2.addr2 = to_iouring_ptr(how.cast_mut());
        if let Some(dest) = file_index {
            sqe.splice_fd_in_or_file_index.file_index = dest.kernel_index_arg();
        }
        Entry(sqe)
    }
);

opcode!(
    /// Modify an epoll file descriptor, equivalent to `epoll_ctl(2)`.
    pub struct EpollCtl {
        epfd: { impl sealed::UseFixed },
        fd: { impl sealed::UseFd },
        op: { i32 },
        ev: { *const epoll_event },
        ;;
    }

    pub const CODE = IoringOp::EpollCtl;

    pub fn build(self) -> Entry {
        let EpollCtl { epfd, fd, op, ev } = self;

        let mut sqe = sqe_zeroed();
        sqe.opcode = Self::CODE;
        assign_fd!(sqe.fd = epfd);
        sqe.addr_or_splice_off_in.addr = to_iouring_ptr(ev.cast_mut());
        sqe.len.len = op as _;
        sqe.off_or_addr2.off = fd as _;
        Entry(sqe)
    }
);

// === 5.7 ===

opcode!(
    /// Splice data to/from a pipe, equivalent to `splice(2)`.
    ///
    /// if `fd_in` refers to a pipe, `off_in` must be `-1`;
    /// The description of `off_in` also applied to `off_out`.
    pub struct Splice {
        fd_in: { impl sealed::UseFixed },
        off_in: { i64 },
        fd_out: { impl sealed::UseFixed },
        off_out: { i64 },
        len: { u32 },
        ;;
        /// see man `splice(2)` for description of flags.
        flags: SpliceFlags = SpliceFlags::empty()
    }

    pub const CODE = IoringOp::Splice;

    pub fn build(self) -> Entry {
        let Splice { fd_in, off_in, fd_out, off_out, len, mut flags } = self;

        let mut sqe = sqe_zeroed();
        sqe.opcode = Self::CODE;
        assign_fd!(sqe.fd = fd_out);
        sqe.len.len = len;
        sqe.off_or_addr2.off = off_out as _;

        sqe.splice_fd_in_or_file_index.splice_fd_in = match fd_in {
            sealed::Target::Fd(fd) => fd,
            sealed::Target::Fixed(i) => {
                flags |= SpliceFlags::FD_IN_FIXED;
                i as _
            }
        };

        sqe.addr_or_splice_off_in.splice_off_in = off_in as _;
        sqe.op_flags.splice_flags = flags;
        Entry(sqe)
    }
);

opcode!(
    /// Register `nbufs` buffers that each have the length `len` with ids starting from `big` in the
    /// group `bgid` that can be used for any request. See
    /// [`BUFFER_SELECT`](crate::types::IoringSqeFlags::BUFFER_SELECT) for more info.
    pub struct ProvideBuffers {
        addr: { *mut u8 },
        len: { i32 },
        nbufs: { u16 },
        bgid: { u16 },
        bid: { u16 }
        ;;
    }

    pub const CODE = IoringOp::ProvideBuffers;

    pub fn build(self) -> Entry {
        let ProvideBuffers { addr, len, nbufs, bgid, bid } = self;

        let mut sqe = sqe_zeroed();
        sqe.opcode = Self::CODE;
        sqe.fd = nbufs as _;
        sqe.addr_or_splice_off_in.addr = to_iouring_ptr(addr);
        sqe.len.len = len as _;
        sqe.off_or_addr2.off = bid as _;
        sqe.buf.buf_group = bgid;
        Entry(sqe)
    }
);

opcode!(
    /// Remove some number of buffers from a buffer group. See
    /// [`BUFFER_SELECT`](crate::types::IoringSqeFlags::BUFFER_SELECT) for more info.
    pub struct RemoveBuffers {
        nbufs: { u16 },
        bgid: { u16 }
        ;;
    }

    pub const CODE = IoringOp::RemoveBuffers;

    pub fn build(self) -> Entry {
        let RemoveBuffers { nbufs, bgid } = self;

        let mut sqe = sqe_zeroed();
        sqe.opcode = Self::CODE;
        sqe.fd = nbufs as _;
        sqe.buf.buf_group = bgid;
        Entry(sqe)
    }
);

// === 5.8 ===

opcode!(
    /// Duplicate pipe content, equivalent to `tee(2)`.
    pub struct Tee {
        fd_in: { impl sealed::UseFixed },
        fd_out: { impl sealed::UseFixed },
        len: { u32 }
        ;;
        flags: SpliceFlags = SpliceFlags::empty()
    }

    pub const CODE = IoringOp::Tee;

    pub fn build(self) -> Entry {
        let Tee { fd_in, fd_out, len, mut flags } = self;

        let mut sqe = sqe_zeroed();
        sqe.opcode = Self::CODE;

        assign_fd!(sqe.fd = fd_out);
        sqe.len.len = len;

        sqe.splice_fd_in_or_file_index.splice_fd_in = match fd_in {
            sealed::Target::Fd(fd) => fd,
            sealed::Target::Fixed(i) => {
                flags |= SpliceFlags::FD_IN_FIXED;
                i as _
            }
        };

        sqe.op_flags.splice_flags = flags;

        Entry(sqe)
    }
);

// === 5.11 ===

opcode!(
    pub struct Shutdown {
        fd: { impl sealed::UseFixed },
        how: { i32 },
        ;;
    }

    pub const CODE = IoringOp::Shutdown;

    pub fn build(self) -> Entry {
        let Shutdown { fd, how } = self;

        let mut sqe = sqe_zeroed();
        sqe.opcode = Self::CODE;
        assign_fd!(sqe.fd = fd);
        sqe.len.len = how as _;
        Entry(sqe)
    }
);

opcode!(
    pub struct RenameAt {
        olddirfd: { impl sealed::UseFd },
        oldpath: { *const libc::c_char },
        newdirfd: { impl sealed::UseFd },
        newpath: { *const libc::c_char },
        ;;
        flags: RenameFlags = RenameFlags::empty()
    }

    pub const CODE = IoringOp::Renameat;

    pub fn build(self) -> Entry {
        let RenameAt {
            olddirfd, oldpath,
            newdirfd, newpath,
            flags
        } = self;

        let mut sqe = sqe_zeroed();
        sqe.opcode = Self::CODE;
        sqe.fd = olddirfd;
        sqe.addr_or_splice_off_in.addr = to_iouring_ptr(oldpath.cast_mut());
        sqe.len.len = newdirfd as _;
        sqe.off_or_addr2.addr2 = to_iouring_ptr(newpath.cast_mut());
        sqe.op_flags.rename_flags = flags;
        Entry(sqe)
    }
);

opcode!(
    pub struct UnlinkAt {
        dirfd: { impl sealed::UseFd },
        pathname: { *const libc::c_char },
        ;;
        flags: AtFlags = AtFlags::empty()
    }

    pub const CODE = IoringOp::Unlinkat;

    pub fn build(self) -> Entry {
        let UnlinkAt { dirfd, pathname, flags } = self;

        let mut sqe = sqe_zeroed();
        sqe.opcode = Self::CODE;
        sqe.fd = dirfd;
        sqe.addr_or_splice_off_in.addr = to_iouring_ptr(pathname.cast_mut());
        sqe.op_flags.unlink_flags = flags;
        Entry(sqe)
    }
);

// === 5.15 ===

opcode!(
    /// Make a directory, equivalent to `mkdirat2(2)`.
    pub struct MkDirAt {
        dirfd: { impl sealed::UseFd },
        pathname: { *const libc::c_char },
        ;;
        mode: libc::mode_t = 0
    }

    pub const CODE = IoringOp::Mkdirat;

    pub fn build(self) -> Entry {
        let MkDirAt { dirfd, pathname, mode } = self;

        let mut sqe = sqe_zeroed();
        sqe.opcode = Self::CODE;
        sqe.fd = dirfd;
        sqe.addr_or_splice_off_in.addr = to_iouring_ptr(pathname.cast_mut());
        sqe.len.len = mode;
        Entry(sqe)
    }
);

opcode!(
    /// Create a symlink, equivalent to `symlinkat2(2)`.
    pub struct SymlinkAt {
        newdirfd: { impl sealed::UseFd },
        target: { *const libc::c_char },
        linkpath: { *const libc::c_char },
        ;;
    }

    pub const CODE = IoringOp::Symlinkat;

    pub fn build(self) -> Entry {
        let SymlinkAt { newdirfd, target, linkpath } = self;

        let mut sqe = sqe_zeroed();
        sqe.opcode = Self::CODE;
        sqe.fd = newdirfd;
        sqe.addr_or_splice_off_in.addr = to_iouring_ptr(target.cast_mut());
        sqe.off_or_addr2.addr2 = to_iouring_ptr(linkpath.cast_mut());
        Entry(sqe)
    }
);

opcode!(
    /// Create a hard link, equivalent to `linkat2(2)`.
    pub struct LinkAt {
        olddirfd: { impl sealed::UseFd },
        oldpath: { *const libc::c_char },
        newdirfd: { impl sealed::UseFd },
        newpath: { *const libc::c_char },
        ;;
        flags: AtFlags = AtFlags::empty()
    }

    pub const CODE = IoringOp::Linkat;

    pub fn build(self) -> Entry {
        let LinkAt { olddirfd, oldpath, newdirfd, newpath, flags } = self;

        let mut sqe = sqe_zeroed();
        sqe.opcode = Self::CODE;
        sqe.fd = olddirfd as _;
        sqe.addr_or_splice_off_in.addr = to_iouring_ptr(oldpath.cast_mut());
        sqe.len.len = newdirfd as _;
        sqe.off_or_addr2.addr2 = to_iouring_ptr(newpath.cast_mut());
        sqe.op_flags.hardlink_flags = flags;
        Entry(sqe)
    }
);

// === 5.18 ===

opcode!(
    /// Send a message (with data) to a target ring.
    pub struct MsgRingData {
        ring_fd: { impl sealed::UseFd },
        result: { i32 },
        user_data: { IoringUserData },
        user_flags: { Option<u32> },
        ;;
        opcode_flags: IoringMsgringFlags = IoringMsgringFlags::empty()
    }

    pub const CODE = IoringOp::MsgRing;

    pub fn build(self) -> Entry {
        let MsgRingData { ring_fd, result, user_data, user_flags, opcode_flags } = self;

        let mut sqe = sqe_zeroed();
        sqe.opcode = Self::CODE;
        sqe.addr_or_splice_off_in.msgring_cmd = IoringMsgringCmds::Data;
        sqe.fd = ring_fd;
        sqe.len.len = result as u32;
        sqe.off_or_addr2.user_data = user_data;
        sqe.op_flags.msg_ring_flags = opcode_flags;
        if let Some(_flags) = user_flags {
            // TODO(lucab): add IORING_MSG_RING_FLAGS_PASS support (in v6.3):
            // https://lore.kernel.org/all/20230103160507.617416-1-leitao@debian.org/t/#u
        }
        Entry(sqe)
    }
);

// === 5.19 ===

opcode!(
    /// A file/device-specific 16-byte command, akin (but not equivalent) to `ioctl(2)`.
    pub struct UringCmd16 {
        fd: { impl sealed::UseFixed },
        cmd_op: { io_uring::cmd_op_struct },
        ;;
        /// Arbitrary command data.
        cmd: [u8; 16] = [0u8; 16]
    }

    pub const CODE = IoringOp::UringCmd;

    pub fn build(self) -> Entry {
        let UringCmd16 { fd, cmd_op, cmd } = self;

        let mut sqe = sqe_zeroed();
        sqe.opcode = Self::CODE;
        assign_fd!(sqe.fd = fd);
        sqe.off_or_addr2.cmd_op = cmd_op;
        unsafe { *sqe.addr3_or_cmd.cmd.as_mut().as_mut_ptr().cast::<[u8; 16]>() = cmd };
        Entry(sqe)
    }
);

opcode!(
    /// A file/device-specific 80-byte command, akin (but not equivalent) to `ioctl(2)`.
    pub struct UringCmd80 {
        fd: { impl sealed::UseFixed },
        cmd_op: { io_uring::cmd_op_struct },
        ;;
        /// Arbitrary command data.
        cmd: [u8; 80] = [0u8; 80]
    }

    pub const CODE = IoringOp::UringCmd;

    pub fn build(self) -> Entry128 {
        let UringCmd80 { fd, cmd_op, cmd } = self;

        let cmd1 = cmd[..16].try_into().unwrap();
        let cmd2 = cmd[16..].try_into().unwrap();

        let mut sqe = sqe_zeroed();
        sqe.opcode = Self::CODE;
        assign_fd!(sqe.fd = fd);
        sqe.off_or_addr2.cmd_op = cmd_op;
        unsafe { *sqe.addr3_or_cmd.cmd.as_mut().as_mut_ptr().cast::<[u8; 16]>() = cmd1 };
        Entry128(Entry(sqe), cmd2)
    }
);

// === 5.19 ===

opcode!(
    /// Create an endpoint for communication, equivalent to `socket(2)`.
    ///
    /// If the `file_index` argument is set, the resulting socket is
    /// directly mapped to the given fixed-file slot instead of being
    /// returned as a normal file descriptor. The application must first
    /// have registered a file table, and the target slot should fit into
    /// it.
    pub struct Socket {
        domain: { i32 },
        socket_type: { i32 },
        protocol: { i32 },
        ;;
        file_index: Option<DestinationSlot> = None,
        flags: ReadWriteFlags = ReadWriteFlags::empty(),
    }

    pub const CODE = IoringOp::Socket;

    pub fn build(self) -> Entry {
        let Socket { domain, socket_type, protocol, file_index, flags } = self;

        let mut sqe = sqe_zeroed();
        sqe.opcode = Self::CODE;
        sqe.fd = domain as _;
        sqe.off_or_addr2.off = socket_type as _;
        sqe.len.len = protocol as _;
        sqe.op_flags.rw_flags = flags;
        if let Some(dest) = file_index {
            sqe.splice_fd_in_or_file_index.file_index = dest.kernel_index_arg();
        }
        Entry(sqe)
    }
);

// === 6.0 ===

opcode!(
    /// Send a message (with fixed FD) to a target ring.
    pub struct MsgRingSendFd {
        ring_fd: { impl sealed::UseFd },
        fixed_slot_src: { Fixed },
        dest_slot_index: { DestinationSlot },
        result: { i32 },
        user_data: { u64 },
        ;;
        opcode_flags: IoringMsgringFlags = IoringMsgringFlags::empty()
    }

    pub const CODE = IoringOp::MsgRing;

    pub fn build(self) -> Entry {
        let MsgRingSendFd { ring_fd, fixed_slot_src, dest_slot_index, result, user_data, opcode_flags } = self;

        let mut sqe = sqe_zeroed();
        sqe.opcode = Self::CODE;
        sqe.addr_or_splice_off_in.msgring_cmd = IoringMsgringCmds::SendFd;
        sqe.fd = ring_fd;
        sqe.len.len = result as u32;
        sqe.off_or_addr2.off = user_data;
        sqe.addr3_or_cmd.addr3.addr3 = fixed_slot_src.0 as u64 ;
        sqe.splice_fd_in_or_file_index.file_index = dest_slot_index.kernel_index_arg();
        sqe.op_flags.msg_ring_flags = opcode_flags;
        Entry(sqe)
    }
);

// === 6.0 ===

opcode!(
    /// Send a zerocopy message on a socket, equivalent to `send(2)`.
    ///
    /// A fixed (pre-mapped) buffer can optionally be used from pre-mapped buffers that have been
    /// previously registered with [`Submitter::register_buffers`](crate::Submitter::register_buffers).
    pub struct SendZc {
        fd: { impl sealed::UseFixed },
        buf: { *const u8 },
        len: { u32 },
        ;;
        /// The `buf_index` is an index into an array of fixed buffers, and is only valid if fixed
        /// buffers were registered.
        ///
        /// The buf and len arguments must fall within a region specified by buf_index in the
        /// previously registered buffer. The buffer need not be aligned with the start of the
        /// registered buffer.
        buf_index: Option<u16> = None,
        flags: SendFlags = SendFlags::empty(),
        zc_flags: IoringSendFlags = IoringSendFlags::empty(),
    }

    pub const CODE = IoringOp::SendZc;

    pub fn build(self) -> Entry {
        let SendZc { fd, buf, len, buf_index, flags, zc_flags } = self;

        let mut sqe = sqe_zeroed();
        sqe.opcode = Self::CODE;
        assign_fd!(sqe.fd = fd);
        sqe.addr_or_splice_off_in.addr = to_iouring_ptr(buf.cast_mut());
        sqe.len.len = len;
        sqe.op_flags.send_flags = flags;
        sqe.ioprio.send_flags = zc_flags;
        if let Some(buf_index) = buf_index {
            sqe.buf.buf_index = buf_index;
            unsafe { sqe.ioprio.send_flags |= IoringSendFlags::FIXED_BUF; }
        }
        Entry(sqe)
    }
);

// === 6.1 ===

opcode!(
    /// Send a zerocopy message on a socket, equivalent to `send(2)`.
    ///
    /// fd must be set to the socket file descriptor, addr must contains a pointer to the msghdr
    /// structure, and flags holds the flags associated with the system call.
    #[derive(Debug)]
    pub struct SendMsgZc {
        fd: { impl sealed::UseFixed },
        msg: { *const libc::msghdr },
        ;;
        ioprio: u16 = 0,
        flags: SendFlags = SendFlags::empty()
    }

    pub const CODE = IoringOp::SendmsgZc;

    pub fn build(self) -> Entry {
        let SendMsgZc { fd, msg, ioprio, flags } = self;

        let mut sqe = sqe_zeroed();
        sqe.opcode = Self::CODE;
        assign_fd!(sqe.fd = fd);
        sqe.ioprio.ioprio = ioprio;
        sqe.addr_or_splice_off_in.addr = to_iouring_ptr(msg.cast_mut());
        sqe.len.len = 1;
        sqe.op_flags.send_flags = flags;
        Entry(sqe)
    }
);
