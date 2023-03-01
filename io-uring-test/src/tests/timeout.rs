use std::time::Instant;

use rustix_uring::types::{Errno, IoringTimeoutFlags, IoringUserData, SubmitArgs, Timespec};
use rustix_uring::{cqueue, opcode, squeue, IoUring};

use crate::Test;

pub fn test_timeout<S: squeue::EntryMarker, C: cqueue::EntryMarker>(
    ring: &mut IoUring<S, C>,
    test: &Test,
) -> anyhow::Result<()> {
    require!(
        test;
        test.probe.is_supported(opcode::Timeout::CODE);
    );

    println!("test timeout");

    // add timeout

    let ts = Timespec {
        tv_sec: 1,
        tv_nsec: 0,
    };
    let timeout_e = opcode::Timeout::new(&ts);

    unsafe {
        let mut queue = ring.submission();
        queue
            .push(
                &timeout_e
                    .build()
                    .user_data(IoringUserData { u64_: 0x09 })
                    .into(),
            )
            .expect("queue is full");
    }

    let start = Instant::now();
    ring.submit_and_wait(1)?;

    assert_eq!(start.elapsed().as_secs(), 1);

    let cqes: Vec<cqueue::Entry> = ring.completion().map(Into::into).collect();

    assert_eq!(cqes.len(), 1);
    assert_eq!(cqes[0].user_data().u64_(), 0x09);
    assert_eq!(cqes[0].result(), -libc::ETIME);

    // add timeout but no

    let ts = Timespec {
        tv_sec: 1,
        tv_nsec: 0,
    };
    let timeout_e = opcode::Timeout::new(&ts);
    let nop_e = opcode::Nop::new();

    unsafe {
        let mut queue = ring.submission();
        queue
            .push(
                &timeout_e
                    .build()
                    .user_data(IoringUserData { u64_: 0x0a })
                    .into(),
            )
            .expect("queue is full");
        queue
            .push(
                &nop_e
                    .build()
                    .user_data(IoringUserData { u64_: 0x0b })
                    .into(),
            )
            .expect("queue is full");
    }

    // nop

    let start = Instant::now();
    ring.submit_and_wait(1)?;

    assert_eq!(start.elapsed().as_secs(), 0);

    let cqes: Vec<cqueue::Entry> = ring.completion().map(Into::into).collect();

    assert_eq!(cqes.len(), 1);
    assert_eq!(cqes[0].user_data().u64_(), 0x0b);
    assert_eq!(cqes[0].result(), 0);

    // timeout

    ring.submit_and_wait(1)?;

    assert_eq!(start.elapsed().as_secs(), 1);

    let cqes: Vec<cqueue::Entry> = ring.completion().map(Into::into).collect();

    assert_eq!(cqes.len(), 1);
    assert_eq!(cqes[0].user_data().u64_(), 0x0a);
    assert_eq!(cqes[0].result(), -libc::ETIME);

    Ok(())
}

pub fn test_timeout_count<S: squeue::EntryMarker, C: cqueue::EntryMarker>(
    ring: &mut IoUring<S, C>,
    test: &Test,
) -> anyhow::Result<()> {
    require!(
        test;
        test.probe.is_supported(opcode::Timeout::CODE);
    );

    println!("test timeout_count");

    let ts = Timespec {
        tv_sec: 1,
        tv_nsec: 0,
    };
    let timeout_e = opcode::Timeout::new(&ts).count(1);
    let nop_e = opcode::Nop::new();

    unsafe {
        let mut queue = ring.submission();
        queue
            .push(
                &timeout_e
                    .build()
                    .user_data(IoringUserData { u64_: 0x0c })
                    .into(),
            )
            .expect("queue is full");
        queue
            .push(
                &nop_e
                    .build()
                    .user_data(IoringUserData { u64_: 0x0d })
                    .into(),
            )
            .expect("queue is full");
    }

    let start = Instant::now();
    ring.submit_and_wait(2)?;

    assert_eq!(start.elapsed().as_secs(), 0);

    let mut cqes: Vec<cqueue::Entry> = ring.completion().map(Into::into).collect();
    cqes.sort_by_key(|cqe| cqe.user_data().u64_());

    assert_eq!(cqes.len(), 2);
    assert_eq!(cqes[0].user_data().u64_(), 0x0c);
    assert_eq!(cqes[1].user_data().u64_(), 0x0d);
    assert_eq!(cqes[0].result(), 0);
    assert_eq!(cqes[1].result(), 0);

    Ok(())
}

pub fn test_timeout_remove<S: squeue::EntryMarker, C: cqueue::EntryMarker>(
    ring: &mut IoUring<S, C>,
    test: &Test,
) -> anyhow::Result<()> {
    require!(
        test;
        test.probe.is_supported(opcode::Timeout::CODE);
        test.probe.is_supported(opcode::TimeoutRemove::CODE);
    );

    println!("test timeout_remove");

    // add timeout

    let ts = Timespec {
        tv_sec: 1,
        tv_nsec: 0,
    };
    let timeout_e = opcode::Timeout::new(&ts);

    unsafe {
        let mut queue = ring.submission();
        queue
            .push(
                &timeout_e
                    .build()
                    .user_data(IoringUserData { u64_: 0x10 })
                    .into(),
            )
            .expect("queue is full");
    }

    ring.submit()?;

    // remove timeout

    let timeout_e = opcode::TimeoutRemove::new(IoringUserData { u64_: 0x10 });

    unsafe {
        let mut queue = ring.submission();
        queue
            .push(
                &timeout_e
                    .build()
                    .user_data(IoringUserData { u64_: 0x11 })
                    .into(),
            )
            .expect("queue is full");
    }

    let start = Instant::now();
    ring.submit_and_wait(2)?;

    assert_eq!(start.elapsed().as_secs(), 0);

    let mut cqes: Vec<cqueue::Entry> = ring.completion().map(Into::into).collect();
    cqes.sort_by_key(|cqe| cqe.user_data().u64_());

    assert_eq!(cqes.len(), 2);
    assert_eq!(cqes[0].user_data().u64_(), 0x10);
    assert_eq!(cqes[1].user_data().u64_(), 0x11);
    assert_eq!(cqes[0].result(), -libc::ECANCELED);
    assert_eq!(cqes[1].result(), 0);

    Ok(())
}

pub fn test_timeout_cancel<S: squeue::EntryMarker, C: cqueue::EntryMarker>(
    ring: &mut IoUring<S, C>,
    test: &Test,
) -> anyhow::Result<()> {
    require!(
        test;
        test.probe.is_supported(opcode::Timeout::CODE);
        test.probe.is_supported(opcode::AsyncCancel::CODE);
    );

    println!("test timeout_cancel");

    // add timeout

    let ts = Timespec {
        tv_sec: 1,
        tv_nsec: 0,
    };
    let timeout_e = opcode::Timeout::new(&ts);

    unsafe {
        let mut queue = ring.submission();
        queue
            .push(
                &timeout_e
                    .build()
                    .user_data(IoringUserData { u64_: 0x10 })
                    .into(),
            )
            .expect("queue is full");
    }

    ring.submit()?;

    // remove timeout

    let timeout_e = opcode::AsyncCancel::new(IoringUserData { u64_: 0x10 });

    unsafe {
        let mut queue = ring.submission();
        queue
            .push(
                &timeout_e
                    .build()
                    .user_data(IoringUserData { u64_: 0x11 })
                    .into(),
            )
            .expect("queue is full");
    }

    let start = Instant::now();
    ring.submit_and_wait(2)?;

    assert_eq!(start.elapsed().as_secs(), 0);

    let mut cqes: Vec<cqueue::Entry> = ring.completion().map(Into::into).collect();
    cqes.sort_by_key(|cqe| cqe.user_data().u64_());

    assert_eq!(cqes.len(), 2);
    assert_eq!(cqes[0].user_data().u64_(), 0x10);
    assert_eq!(cqes[1].user_data().u64_(), 0x11);
    assert_eq!(cqes[0].result(), -libc::ECANCELED);
    assert_eq!(cqes[1].result(), 0);

    Ok(())
}

pub fn test_timeout_abs<S: squeue::EntryMarker, C: cqueue::EntryMarker>(
    ring: &mut IoUring<S, C>,
    test: &Test,
) -> anyhow::Result<()> {
    require!(
        test;
        test.probe.is_supported(opcode::Timeout::CODE);
    );

    println!("test timeout_abs");

    let mut now = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };

    let ret = unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut now) };

    assert_eq!(ret, 0);

    let ts = Timespec {
        tv_sec: now.tv_sec + 2,
        tv_nsec: now.tv_nsec,
    };

    let timeout_e = opcode::Timeout::new(&ts).flags(IoringTimeoutFlags::ABS);

    unsafe {
        let mut queue = ring.submission();
        queue
            .push(
                &timeout_e
                    .build()
                    .user_data(IoringUserData { u64_: 0x19 })
                    .into(),
            )
            .expect("queue is full");
    }

    let start = Instant::now();
    ring.submit_and_wait(1)?;

    assert!(start.elapsed().as_secs() >= 1);

    let cqes: Vec<cqueue::Entry> = ring.completion().map(Into::into).collect();

    assert_eq!(cqes.len(), 1);
    assert_eq!(cqes[0].user_data().u64_(), 0x19);
    assert_eq!(cqes[0].result(), -libc::ETIME);

    Ok(())
}

pub fn test_timeout_submit_args<S: squeue::EntryMarker, C: cqueue::EntryMarker>(
    ring: &mut IoUring<S, C>,
    test: &Test,
) -> anyhow::Result<()> {
    require! {
        test;
        ring.params().is_feature_ext_arg();
    };

    println!("test timeout_submit_args");

    let ts = Timespec {
        tv_sec: 1,
        tv_nsec: 0,
    };
    let args = SubmitArgs::new().timespec(&ts);

    // timeout

    let start = Instant::now();
    match ring.submitter().submit_with_args(1, &args) {
        Ok(_) => panic!(),
        Err(err) if err == Errno::TIME => (),
        Err(err) => return Err(err.into()),
    }
    assert_eq!(start.elapsed().as_secs(), 1);

    assert!(ring.completion().next().is_none());

    // no timeout

    let nop_e = opcode::Nop::new();

    unsafe {
        ring.submission()
            .push(
                &nop_e
                    .build()
                    .user_data(IoringUserData { u64_: 0x1c })
                    .into(),
            )
            .expect("queue is full");
    }

    let start = Instant::now();
    ring.submitter().submit_with_args(1, &args)?;
    assert_eq!(start.elapsed().as_secs(), 0);

    let cqes: Vec<cqueue::Entry> = ring.completion().map(Into::into).collect();

    assert_eq!(cqes.len(), 1);
    assert_eq!(cqes[0].user_data().u64_(), 0x1c);
    assert_eq!(cqes[0].result(), 0);

    Ok(())
}
