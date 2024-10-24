// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use libc::{RTA_DST, RTA_IFP};

pub const ALIGN: usize = 4;

pub const RTM_ADDRS: i32 = RTA_DST | RTA_IFP;

#[allow(non_camel_case_types)]
pub type rt_msghdr = libc::rt_msghdr;
