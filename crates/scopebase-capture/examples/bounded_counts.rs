// SPDX-License-Identifier: Apache-2.0
//! Known bounds versus unknown uppers: absence of a bound is not zero.
//! NEW (CP11): reference-only; no donor lines copied.
use scopebase_capture::{
    quantity::{Bytes, Count, CountBounds, Events},
    ContractError,
};

fn main() -> Result<(), ContractError> {
    let exact = CountBounds::new(Count::new(5), Some(Count::<Events>::new(5)))?;
    assert_eq!(exact.lower(), Count::new(5));
    assert_eq!(exact.upper(), Some(Count::new(5)));
    println!("exact bound: {exact:?}");
    // Unknown upper, including at zero: nothing proves absence of more.
    let open = CountBounds::new(Count::new(0), None::<Count<Events>>)?;
    assert_eq!(open.lower(), Count::new(0));
    assert_eq!(open.upper(), None);
    println!("open bound: {open:?}");
    let bytes = Count::<Bytes>::new(5);
    assert_eq!(bytes.get(), 5);
    println!("copy bytes survive as an exact count: {bytes:?}");
    assert_eq!(
        CountBounds::new(Count::new(6), Some(Count::<Events>::new(5))).expect_err("reversed refuses"),
        ContractError::ReversedBounds
    );
    println!("reversed bounds refuse with ReversedBounds");
    assert_eq!(
        Count::<Events>::new(u64::MAX)
            .checked_add(Count::new(1))
            .expect_err("overflow refuses"),
        ContractError::ArithmeticOverflow
    );
    println!("overflowing addition refuses with ArithmeticOverflow");
    Ok(())
}
