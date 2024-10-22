// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

pub const ALIGN: usize = 8;

#[allow(non_camel_case_types, clippy::struct_field_names)]
#[repr(C, align(8))]
pub struct rt_metrics {
    pub rmx_locks: u64,           // Kernel must leave these values alone
    pub rmx_mtu: u64,             // MTU for this path
    pub rmx_hopcount: u64,        // max hops expected
    pub rmx_recvpipe: u64,        // inbound delay-bandwidth product
    pub rmx_sendpipe: u64,        // outbound delay-bandwidth product
    pub rmx_ssthresh: u64,        // outbound gateway buffer limit
    pub rmx_rtt: u64,             // estimated round trip time
    pub rmx_rttvar: u64,          // estimated rtt variance
    pub rmx_expire: libc::time_t, // lifetime for route, e.g. redirect
    pub rmx_pksent: libc::time_t, // packets sent using this route
}

// The BSDs are lacking `rt_msghdr` in their libc bindings.
#[allow(non_camel_case_types, clippy::struct_field_names)]
#[repr(C, align(8))]
pub struct rt_msghdr {
    pub rtm_msglen: libc::c_ushort, // to skip over non-understood messages
    pub rtm_version: libc::c_uchar, // future binary compatibility
    pub rtm_type: libc::c_uchar,    // message type
    pub rtm_index: libc::c_ushort,  // index for associated ifp
    pub rtm_flags: libc::c_int,     // flags, incl. kern & message, e.g. DONE
    pub rtm_addrs: libc::c_int,     // bitmask identifying sockaddrs in msg
    pub rtm_pid: libc::pid_t,       // identify sender
    pub rtm_seq: libc::c_int,       // for sender to identify action
    pub rtm_errno: libc::c_int,     // why failed
    pub rtm_use: libc::c_int,       // from rtentry
    pub rtm_inits: libc::c_int,     // which metrics we are initializing
    pub rtm_rmx: rt_metrics,        // metrics themselves
}
