use rustix_uring::{cqueue, squeue, IoUring};

use crate::Test;

pub fn test_issue154<S: squeue::EntryMarker, C: cqueue::EntryMarker>(
    _ring: &mut IoUring<S, C>,
    test: &Test,
) -> anyhow::Result<()> {
    require! {
        test;
    }

    println!("test issue #154");

    let err = match IoUring::new(u32::MAX) {
        Ok(_) => panic!(),
        Err(err) => err,
    };
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);

    Ok(())
}
