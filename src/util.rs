use core::ffi::c_void;
use core::ptr;
use core::sync::atomic;

use rustix::io;
use rustix::mm::{madvise, mmap, munmap, Advice, MapFlags, ProtFlags};

use crate::types::OwnedFd;

/// A region of memory mapped using `mmap(2)`.
pub struct Mmap {
    addr: ptr::NonNull<c_void>,
    len: usize,
}

impl Mmap {
    /// Map `len` bytes starting from the offset `offset` in the file descriptor `fd` into memory.
    pub fn new(fd: &OwnedFd, offset: u64, len: usize) -> io::Result<Mmap> {
        unsafe {
            mmap(
                ptr::null_mut(),
                len,
                ProtFlags::READ | ProtFlags::WRITE,
                MapFlags::SHARED | MapFlags::POPULATE,
                fd,
                offset,
            )
            .map(|addr| {
                // here, `mmap` will never return null
                let addr = ptr::NonNull::new_unchecked(addr);
                Mmap { addr, len }
            })
        }
    }

    /// Do not make the stored memory accessible by child processes after a `fork`.
    pub fn dontfork(&self) -> io::Result<()> {
        unsafe { madvise(self.addr.as_ptr(), self.len, Advice::LinuxDontFork) }
    }

    /// Get a pointer to the memory.
    #[inline]
    pub fn as_mut_ptr(&self) -> *mut c_void {
        self.addr.as_ptr()
    }

    /// Get a pointer to the data at the given offset.
    #[inline]
    pub unsafe fn offset(&self, offset: u32) -> *mut c_void {
        self.as_mut_ptr().add(offset as usize)
    }
}

impl Drop for Mmap {
    fn drop(&mut self) {
        unsafe {
            munmap(self.addr.as_ptr(), self.len).ok();
        }
    }
}

#[inline(always)]
pub unsafe fn unsync_load(u: *const atomic::AtomicU32) -> u32 {
    *u.cast::<u32>()
}

#[inline]
pub const fn cast_ptr<T>(n: &T) -> *const T {
    n
}
