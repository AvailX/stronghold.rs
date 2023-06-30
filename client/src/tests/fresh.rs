// Copyright 2020-2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

pub use crate::procedures::Slip10Chain;
use crypto::keys::slip10;
use std::fmt::Write;
pub use stronghold_utils::{random::*, test_utils};

use crate::Location;

/// Generates a random [`Location`].
pub fn location() -> Location {
    Location::generic(variable_bytestring(4096), variable_bytestring(4096))
}

/// Creates a random SLIP10 hardened chain.
pub fn slip10_hd_chain() -> (String, Slip10Chain) {
    use slip10::Segment;
    let mut s = "m".to_string();
    let mut is = vec![];
    while coinflip() {
        let i = random::<u32>() & 0x7fffff;
        write!(&mut s, "/{}'", i).expect("Failed appending path segment");
        is.push(i.harden().into());
    }
    (s, is)
}
