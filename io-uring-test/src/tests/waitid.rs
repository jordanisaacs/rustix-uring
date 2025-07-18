use ::core::mem::MaybeUninit;
use ::std::process::{Command, Stdio};

use ::io_uring::{cqueue, opcode, squeue, types, IoUring};
use ::rustix::process;

use crate::Test;

pub fn test_waitid<S: squeue::EntryMarker, C: cqueue::EntryMarker>(
    ring: &mut IoUring<S, C>,
    test: &Test,
) -> anyhow::Result<()> {
    require!(
        test;
        test.probe.is_supported(opcode::Waitid::CODE);
    );

    println!("test waitid");

    #[allow(clippy::zombie_processes)]
    let child = Command::new("yes")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("failed to execute child");

    let pid = process::Pid::from_child(&child);
    let pgid = process::getpgid(Some(pid)).unwrap();

    let mut status = MaybeUninit::<types::WaitIdStatus>::uninit();
    let status = unsafe { status.assume_init_mut() };

    // Test waiting for the process by pid.

    unsafe { ::libc::kill(child.id() as _, ::libc::SIGSTOP) };
    let sqe = opcode::Waitid::new(types::WaitId::Pid(pid), status)
        .options(types::WaitIdOptions::STOPPED)
        .build()
        .user_data(0x666)
        .into();
    unsafe { ring.submission().push(&sqe) }?;
    ring.submit_and_wait(1)?;
    for cqe in ring.completion().map(Into::<cqueue::Entry>::into).take(1) {
        assert_eq!(cqe.user_data_u64(), 0x666);
        cqe.result()?;
    }
    #[cfg(not(any(target_os = "fuchsia", target_os = "netbsd")))]
    assert_eq!(status.stopping_signal(), Some(::libc::SIGSTOP as _));
    assert_eq!(status.raw_signo(), ::libc::SIGCHLD);
    assert_eq!(status.raw_errno(), 0);
    assert_eq!(status.raw_code(), ::libc::CLD_STOPPED);

    unsafe { ::libc::kill(child.id() as _, ::libc::SIGCONT) };
    let sqe = opcode::Waitid::new(types::WaitId::Pid(pid), status)
        .options(types::WaitIdOptions::CONTINUED)
        .build()
        .user_data(0x666)
        .into();
    unsafe { ring.submission().push(&sqe) }?;
    ring.submit_and_wait(1)?;
    for cqe in ring.completion().map(Into::<cqueue::Entry>::into).take(1) {
        assert_eq!(cqe.user_data_u64(), 0x666);
        cqe.result()?;
    }
    assert!(status.continued());

    // Now do the same thing with the pgid.

    unsafe { ::libc::kill(child.id() as _, ::libc::SIGSTOP) };

    let sqe = opcode::Waitid::new(types::WaitId::Pgid(Some(pgid)), status)
        .options(types::WaitIdOptions::STOPPED)
        .build()
        .user_data(0x666)
        .into();
    unsafe { ring.submission().push(&sqe) }?;
    ring.submit_and_wait(1)?;
    for cqe in ring.completion().map(Into::<cqueue::Entry>::into).take(1) {
        assert_eq!(cqe.user_data_u64(), 0x666);
        cqe.result()?;
    }
    #[cfg(not(any(target_os = "fuchsia", target_os = "netbsd")))]
    assert_eq!(status.stopping_signal(), Some(::libc::SIGSTOP as _));
    assert_eq!(status.raw_signo(), ::libc::SIGCHLD);
    assert_eq!(status.raw_errno(), 0);
    assert_eq!(status.raw_code(), ::libc::CLD_STOPPED);

    unsafe { ::libc::kill(child.id() as _, ::libc::SIGCONT) };

    let sqe = opcode::Waitid::new(types::WaitId::Pgid(Some(pgid)), status)
        .options(types::WaitIdOptions::CONTINUED)
        .build()
        .user_data(0x666)
        .into();
    unsafe { ring.submission().push(&sqe) }?;
    ring.submit_and_wait(1)?;
    for cqe in ring.completion().map(Into::<cqueue::Entry>::into).take(1) {
        assert_eq!(cqe.user_data_u64(), 0x666);
        cqe.result()?;
    }
    assert!(status.continued());

    // Finish

    unsafe { ::libc::kill(child.id() as _, ::libc::SIGKILL) };

    let sqe = opcode::Waitid::new(types::WaitId::Pid(pid), status)
        .options(types::WaitIdOptions::EXITED | types::WaitIdOptions::NOWAIT)
        .build()
        .user_data(0x666)
        .into();
    unsafe { ring.submission().push(&sqe) }?;
    ring.submit_and_wait(1)?;
    for cqe in ring.completion().map(Into::<cqueue::Entry>::into).take(1) {
        assert_eq!(cqe.user_data_u64(), 0x666);
        cqe.result()?;
    }
    assert!(status.killed());
    #[cfg(not(any(target_os = "fuchsia", target_os = "netbsd")))]
    assert_eq!(status.terminating_signal(), Some(::libc::SIGKILL as _));

    let sqe = opcode::Waitid::new(types::WaitId::Pid(pid), status)
        .options(types::WaitIdOptions::EXITED)
        .build()
        .user_data(0x666)
        .into();
    unsafe { ring.submission().push(&sqe) }?;
    ring.submit_and_wait(1)?;
    for cqe in ring.completion().map(Into::<cqueue::Entry>::into).take(1) {
        assert_eq!(cqe.user_data_u64(), 0x666);
        cqe.result()?;
    }
    assert!(status.killed());
    #[cfg(not(any(target_os = "fuchsia", target_os = "netbsd")))]
    assert_eq!(status.terminating_signal(), Some(::libc::SIGKILL as _));

    Ok(())
}
