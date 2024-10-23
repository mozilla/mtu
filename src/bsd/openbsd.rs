// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

pub const ALIGN: usize = 8;

#[allow(non_camel_case_types, clippy::struct_field_names)]
#[repr(C)]
pub struct rt_metrics {
    pub rmx_pksent: u64,          // packets sent using this route
    pub rmx_expire: i64,          // lifetime for route, e.g. redirect
    pub rmx_locks: libc::c_uint,  // Kernel must leave these values
    pub rmx_mtu: libc::c_uint,    // MTU for this path
    pub rmx_refcnt: libc::c_uint, // # references hold
    // some apps may still need these no longer used metrics
    pub rmx_hopcount: libc::c_uint, // max hops expected
    pub rmx_recvpipe: libc::c_uint, // inbound delay-bandwidth product
    pub rmx_sendpipe: libc::c_uint, // outbound delay-bandwidth product
    pub rmx_ssthresh: libc::c_uint, // outbound gateway buffer limit
    pub rmx_rtt: libc::c_uint,      // estimated round trip time
    pub rmx_rttvar: libc::c_uint,   // estimated rtt variance
    pub rmx_pad: libc::c_uint,
}

#[allow(non_camel_case_types, clippy::struct_field_names)]
#[repr(C)]
pub struct rt_msghdr {
    pub rtm_msglen: libc::c_ushort, // to skip over non-understood messages
    pub rtm_version: libc::c_uchar, // future binary compatibility
    pub rtm_type: libc::c_uchar,    // message type
    pub rtm_hdrlen: libc::c_ushort, // sizeof(rt_msghdr) to skip over the header
    pub rtm_index: libc::c_ushort,  // index for associated ifp
    pub rtm_tableid: libc::c_ushort, // routing table id
    pub rtm_priority: libc::c_uchar, // routing priority
    pub rtm_mpls: libc::c_uchar,    // MPLS additional infos
    pub rtm_addrs: libc::c_int,     // bitmask identifying sockaddrs in msg
    pub rtm_flags: libc::c_int,     // flags, incl. kern & message, e.g. DONE
    pub rtm_fmask: libc::c_int,     // bitmask used in RTM_CHANGE message
    pub rtm_pid: libc::pid_t,       // identify sender
    pub rtm_seq: libc::c_int,       // for sender to identify action
    pub rtm_errno: libc::c_int,     // why failed
    pub rtm_inits: libc::c_uint,    // which metrics we are initializing
    pub rtm_rmx: rt_metrics,        // metrics themselves
}
