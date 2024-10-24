// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

pub const RTM_ADDRS: i32 = libc::RTA_DST | libc::RTA_IFP;

// See https://github.com/freebsd/freebsd-src/blob/524a425d30fce3d5e47614db796046830b1f6a83/sys/net/route.h#L362-L371
pub const ALIGN: usize = std::mem::size_of::<libc::c_long>();

#[allow(non_camel_case_types, clippy::struct_field_names)]
#[repr(C)]
// See https://github.com/freebsd/freebsd-src/blob/524a425d30fce3d5e47614db796046830b1f6a83/sys/net/route.h#L79-L93
pub struct rt_metrics {
    pub rmx_locks: libc::c_ulong,    // Kernel must leave these values alone
    pub rmx_mtu: libc::c_ulong,      // MTU for this path
    pub rmx_hopcount: libc::c_ulong, // max hops expected
    pub rmx_expire: libc::c_ulong,   // lifetime for route, e.g. redirect
    pub rmx_recvpipe: libc::c_ulong, // inbound delay-bandwidth product
    pub rmx_sendpipe: libc::c_ulong, // outbound delay-bandwidth product
    pub rmx_ssthresh: libc::c_ulong, // outbound gateway buffer limit
    pub rmx_rtt: libc::c_ulong,      // estimated round trip time
    pub rmx_rttvar: libc::c_ulong,   // estimated rtt variance
    pub rmx_pksent: libc::c_ulong,   // packets sent using this route
    pub rmx_weight: libc::u_long,    // route weight
    pub rmx_nhidx: libc::u_long,     // route nexhop index
    pub rmx_filler: [libc::c_ulong; 2], // will be used for T/TCP later
}

#[allow(non_camel_case_types, clippy::struct_field_names)]
#[repr(C)]
// See https://github.com/freebsd/freebsd-src/blob/524a425d30fce3d5e47614db796046830b1f6a83/sys/net/route.h#L249-L263
pub struct rt_msghdr {
    pub rtm_msglen: libc::c_ushort, // to skip over non-understood messages
    pub rtm_version: libc::c_uchar, // future binary compatibility
    pub rtm_type: libc::c_uchar,    // message type
    pub rtm_index: libc::c_ushort,  // index for associated ifp
    pub _rtm_spare1: libc::c_ushort,
    pub rtm_flags: libc::c_int,  // flags, incl. kern & message, e.g. DONE
    pub rtm_addrs: libc::c_int,  // bitmask identifying sockaddrs in msg
    pub rtm_pid: libc::pid_t,    // identify sender
    pub rtm_seq: libc::c_int,    // for sender to identify action
    pub rtm_errno: libc::c_int,  // why failed
    pub rtm_fmask: libc::c_int,  // bitmask used in RTM_CHANGE message
    pub rtm_inits: libc::u_long, // which metrics we are initializing
    pub rtm_rmx: rt_metrics,     // metrics themselves
}
