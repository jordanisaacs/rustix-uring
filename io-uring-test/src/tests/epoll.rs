use crate::Test;
use ::core::{mem::MaybeUninit, time::Duration};
use ::rustix::{event::epoll, fd::OwnedFd, io, pipe};
use ::std::{
    os::fd::{AsFd, BorrowedFd},
    thread,
};
use io_uring::{cqueue, opcode, squeue, types, IoUring};
use std::os::unix::io::AsRawFd;

// Tests translated from liburing/test/epwait.c.

#[derive(Debug)]
struct RxTxPipe {
    rx: OwnedFd,
    tx: OwnedFd,
}

pub fn test_ready<S: squeue::EntryMarker, C: cqueue::EntryMarker>(
    ring: &mut IoUring<S, C>,
    test: &Test,
) -> anyhow::Result<()> {
    require!(
        test;
        test.probe.is_supported(opcode::EpollWait::CODE);
    );

    println!("test ready");

    const NPIPES: usize = 2;
    let (efd, pipes, mut events) = init::<NPIPES>()?;

    for pipe in &pipes {
        let tx = pipe.tx.as_fd();
        io::write(tx, b"foo")?;
    }

    let sqe = opcode::EpollWait::new(types::Fd(efd.as_raw_fd()), events.as_mut_ptr(), NPIPES as _)
        .build()
        .user_data(0x666)
        .into();
    unsafe { ring.submission().push(&sqe) }?;

    ring.submit_and_wait(1)?;
    for cqe in ring.completion().map(Into::<cqueue::Entry>::into).take(1) {
        assert_eq!(cqe.user_data_u64(), 0x666);
        cqe.result()?;
    }

    let mut tmp = [0u8; 16];

    for event in &events {
        let fd = unsafe { BorrowedFd::borrow_raw(event.data.u64() as _) };
        io::read(fd, &mut tmp)?;
    }

    Ok(())
}

pub fn test_not_ready<S: squeue::EntryMarker, C: cqueue::EntryMarker>(
    ring: &mut IoUring<S, C>,
    test: &Test,
) -> anyhow::Result<()> {
    require!(
        test;
        test.probe.is_supported(opcode::EpollWait::CODE);
    );

    println!("test not ready");

    const NPIPES: usize = 2;
    let (efd, pipes, mut events) = init::<NPIPES>()?;

    let sqe = opcode::EpollWait::new(types::Fd(efd.as_raw_fd()), events.as_mut_ptr(), NPIPES as _)
        .build()
        .user_data(0x666)
        .into();
    unsafe { ring.submission().push(&sqe) }?;

    for pipe in &pipes {
        thread::sleep(Duration::from_micros(10000));
        let tx = pipe.tx.as_fd();
        io::write(tx, b"foo")?;
    }

    let mut nr = 0;
    ring.submit_and_wait(1)?;
    for cqe in ring.completion().map(Into::<cqueue::Entry>::into).take(1) {
        assert_eq!(cqe.user_data_u64(), 0x666);
        nr = cqe.result()?;
        assert!(nr.cast_signed() >= 0);
    }

    let mut tmp = [0u8; 16];

    for event in events.iter().take(nr as _) {
        let fd = unsafe { BorrowedFd::borrow_raw(event.data.u64() as _) };
        io::read(fd, &mut tmp)?;
    }

    Ok(())
}

pub fn test_delete<S: squeue::EntryMarker, C: cqueue::EntryMarker>(
    ring: &mut IoUring<S, C>,
    test: &Test,
) -> anyhow::Result<()> {
    require!(
        test;
        test.probe.is_supported(opcode::EpollWait::CODE);
    );

    println!("test delete");

    const NPIPES: usize = 2;
    let (efd, pipes, mut events) = init::<NPIPES>()?;

    let sqe = opcode::EpollWait::new(types::Fd(efd.as_raw_fd()), events.as_mut_ptr(), NPIPES as _)
        .build()
        .user_data(0x666)
        .into();
    unsafe { ring.submission().push(&sqe) }?;

    epoll::delete(efd.as_fd(), pipes[0].rx.as_fd())?;

    let mut tmp = [0u8; 16];

    for pipe in &pipes {
        io::write(pipe.tx.as_fd(), &tmp)?;
    }

    ring.submit_and_wait(1)?;
    for cqe in ring.completion().map(Into::<cqueue::Entry>::into).take(1) {
        assert_eq!(cqe.user_data_u64(), 0x666);
        cqe.result()?;
    }

    for pipe in &pipes {
        io::read(pipe.rx.as_fd(), &mut tmp)?;
    }

    let data = epoll::EventData::new_u64(pipes[0].rx.as_raw_fd().cast_unsigned().into());
    let flags = epoll::EventFlags::IN;
    epoll::add(efd, pipes[0].rx.as_fd(), data, flags)?;

    Ok(())
}

pub fn test_remove<S: squeue::EntryMarker, C: cqueue::EntryMarker>(
    ring: &mut IoUring<S, C>,
    test: &Test,
) -> anyhow::Result<()> {
    require!(
        test;
        test.probe.is_supported(opcode::EpollWait::CODE);
    );

    println!("test remove");

    const NPIPES: usize = 2;
    let (efd, pipes, mut events) = init::<NPIPES>()?;

    let sqe = opcode::EpollWait::new(types::Fd(efd.as_raw_fd()), events.as_mut_ptr(), NPIPES as _)
        .build()
        .user_data(0x666)
        .into();
    unsafe { ring.submission().push(&sqe) }?;

    drop(efd);

    thread::sleep(Duration::from_micros(10000));
    for pipe in &pipes {
        io::write(pipe.tx.as_fd(), b"foo")?;
    }

    ring.submit_and_wait(1)?;
    for cqe in ring.completion().map(Into::<cqueue::Entry>::into).take(1) {
        assert_eq!(cqe.user_data_u64(), 0x666);
        let err = cqe.result().unwrap_err();
        assert!([io::Errno::AGAIN, io::Errno::BADF].contains(&err));
    }

    Ok(())
}

pub fn test_race<S: squeue::EntryMarker, C: cqueue::EntryMarker>(
    ring: &mut IoUring<S, C>,
    test: &Test,
) -> anyhow::Result<()> {
    require!(
        test;
        test.probe.is_supported(opcode::EpollWait::CODE);
    );

    println!("test race");

    const LOOPS: usize = 500;
    const NPIPES: usize = 8;

    fn prune(events: &[epoll::Event], nr: usize) -> anyhow::Result<()> {
        let mut tmp = [0u8; 32];

        for event in events.iter().take(nr) {
            let fd = unsafe { BorrowedFd::borrow_raw(event.data.u64() as _) };
            io::read(fd, &mut tmp)?;
        }

        Ok(())
    }

    thread::scope(|scope| -> anyhow::Result<()> {
        let (efd, pipes, mut events) = init::<NPIPES>()?;

        let handle = scope.spawn(move || -> anyhow::Result<()> {
            for _ in 0..LOOPS {
                thread::sleep(Duration::from_micros(150));
                for pipe in &pipes {
                    io::write(pipe.tx.as_fd(), b"foo")?;
                }
            }
            Ok(())
        });

        for _ in 0..LOOPS {
            let sqe = opcode::EpollWait::new(
                types::Fd(efd.as_raw_fd()),
                events.as_mut_ptr(),
                NPIPES as _,
            )
            .build()
            .user_data(0x666)
            .into();
            unsafe { ring.submission().push(&sqe) }?;
            ring.submit_and_wait(1)?;
            let cqe = ring
                .completion()
                .next()
                .map(Into::<cqueue::Entry>::into)
                .unwrap();
            assert_eq!(cqe.user_data_u64(), 0x666);
            let nr = cqe.result()?;
            prune(&events, nr as _)?;
            thread::sleep(Duration::from_micros(100));
        }

        handle.join().unwrap()?;

        Ok(())
    })?;

    Ok(())
}

fn init<const NPIPES: usize>(
) -> anyhow::Result<(OwnedFd, [RxTxPipe; NPIPES], [epoll::Event; NPIPES])> {
    let pipes: [RxTxPipe; NPIPES] = {
        let mut pipes: [MaybeUninit<RxTxPipe>; NPIPES] = [const { MaybeUninit::uninit() }; NPIPES];
        for pipe in &mut pipes {
            let (rx, tx) = pipe::pipe()?;
            pipe.write(RxTxPipe { rx, tx });
        }
        unsafe { ::core::mem::transmute_copy(&pipes) }
    };

    let efd = epoll::create(epoll::CreateFlags::empty())?;

    for pipe in &pipes {
        let efd = efd.as_fd();
        let rx = pipe.rx.as_fd();
        let data = epoll::EventData::new_u64(rx.as_raw_fd().cast_unsigned().into());
        let flags = epoll::EventFlags::IN;
        epoll::add(efd, rx, data, flags)?;
    }

    let events: [epoll::Event; NPIPES] = unsafe { ::core::mem::zeroed() };

    Ok((efd, pipes, events))
}
