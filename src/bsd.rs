// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::{
    io::Error,
    mem::{self, size_of},
    net::IpAddr,
    num::TryFromIntError,
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
    ptr, slice, str,
};

#[cfg(not(bsd))]
use libc::rt_msghdr;
use libc::{
    getpid, read, sockaddr_dl, sockaddr_in, sockaddr_in6, sockaddr_storage, socket, write, AF_INET,
    AF_INET6, AF_UNSPEC, PF_ROUTE, RTAX_IFP, RTAX_MAX, RTA_DST, RTA_IFP, RTM_GET, RTM_VERSION,
    SOCK_RAW,
};

// The BSDs are lacking `rt_metrics` in their libc bindings.
// And of course they are all slightly different.
#[cfg(target_os = "freebsd")]
#[allow(non_camel_case_types, clippy::struct_field_names)]
#[repr(C)]
struct rt_metrics {
    rmx_locks: libc::c_ulong,       // Kernel must leave these values alone
    rmx_mtu: libc::c_ulong,         // MTU for this path
    rmx_hopcount: libc::c_ulong,    // max hops expected
    rmx_expire: libc::c_ulong,      // lifetime for route, e.g. redirect
    rmx_recvpipe: libc::c_ulong,    // inbound delay-bandwidth product
    rmx_sendpipe: libc::c_ulong,    // outbound delay-bandwidth product
    rmx_ssthresh: libc::c_ulong,    // outbound gateway buffer limit
    rmx_rtt: libc::c_ulong,         // estimated round trip time
    rmx_rttvar: libc::c_ulong,      // estimated rtt variance
    rmx_pksent: libc::c_ulong,      // packets sent using this route
    rmx_weight: libc::u_long,       // route weight
    rmx_nhidx: libc::u_long,        // route nexhop index
    rmx_filler: [libc::c_ulong; 2], // will be used for T/TCP later
}

#[cfg(target_os = "netbsd")]
#[allow(non_camel_case_types, clippy::struct_field_names)]
#[repr(C)]
struct rt_metrics {
    rmx_locks: libc::uint64_t,    // Kernel must leave these values alone
    rmx_mtu: libc::uint64_t,      // MTU for this path
    rmx_hopcount: libc::uint64_t, // max hops expected
    rmx_recvpipe: libc::uint64_t, // inbound delay-bandwidth product
    rmx_sendpipe: libc::uint64_t, // outbound delay-bandwidth product
    rmx_ssthresh: libc::uint64_t, // outbound gateway buffer limit
    rmx_rtt: libc::uint64_t,      // estimated round trip time
    rmx_rttvar: libc::uint64_t,   // estimated rtt variance
    rmx_expire: libc::time_t,     // lifetime for route, e.g. redirect
    rmx_pksent: libc::time_t,     // packets sent using this route
}

#[cfg(target_os = "openbsd")]
#[allow(non_camel_case_types, clippy::struct_field_names)]
#[repr(C)]
struct rt_metrics {
    rmx_pksent: libc::uint64_t, // packets sent using this route
    rmx_expire: libc::int64_t,  // lifetime for route, e.g. redirect
    rmx_locks: libc::c_uint,    // Kernel must leave these values
    rmx_mtu: libc::c_uint,      // MTU for this path
    rmx_refcnt: libc::c_uint,   // # references hold
    // some apps may still need these no longer used metrics
    rmx_hopcount: libc::c_uint, // max hops expected
    rmx_recvpipe: libc::c_uint, // inbound delay-bandwidth product
    rmx_sendpipe: libc::c_uint, // outbound delay-bandwidth product
    rmx_ssthresh: libc::c_uint, // outbound gateway buffer limit
    rmx_rtt: libc::c_uint,      // estimated round trip time
    rmx_rttvar: libc::c_uint,   // estimated rtt variance
    rmx_pad: libc::c_uint,
}

// The BSDs are lacking `rt_msghdr` in their libc bindings.
#[cfg(bsd)]
#[allow(non_camel_case_types, clippy::struct_field_names)]
#[repr(C)]
struct rt_msghdr {
    rtm_msglen: libc::c_ushort, // to skip over non-understood messages
    rtm_version: libc::c_uchar, // future binary compatibility
    rtm_type: libc::c_uchar,    // message type
    rtm_index: libc::c_ushort,  // index for associated ifp
    rtm_flags: libc::c_int,     // flags, incl kern & message, e.g. DONE
    rtm_addrs: libc::c_int,     // bitmask identifying sockaddrs in msg
    rtm_pid: libc::pid_t,       // identify sender
    rtm_seq: libc::c_int,       // for sender to identify action
    rtm_errno: libc::c_int,     // why failed
    rtm_use: libc::c_int,       // from rtentry
    rtm_inits: libc::c_ulong,   // which metrics we are initializing
    rtm_rmx: rt_metrics,        // metrics themselves
}

use crate::{default_err, next_item_aligned_by_four, unlikely_err};

pub fn interface_and_mtu_impl(remote: IpAddr) -> Result<(String, usize), Error> {
    // Open route socket.
    let fd = unsafe { socket(PF_ROUTE, SOCK_RAW, AF_UNSPEC) };
    if fd == -1 {
        return Err(Error::last_os_error());
    }
    let fd = unsafe { OwnedFd::from_raw_fd(fd) };

    // Prepare buffer with destination `sockaddr`.
    let mut dst: sockaddr_storage = unsafe { mem::zeroed() };
    match remote {
        IpAddr::V4(ip) => {
            let sin = unsafe { &mut *ptr::from_mut(&mut dst).cast::<sockaddr_in>() };
            sin.sin_len = size_of::<sockaddr_in>()
                .try_into()
                .map_err(|e: TryFromIntError| unlikely_err(e.to_string()))?;
            sin.sin_family = AF_INET
                .try_into()
                .map_err(|e: TryFromIntError| unlikely_err(e.to_string()))?;
            sin.sin_addr.s_addr = u32::from_ne_bytes(ip.octets());
        }
        IpAddr::V6(ip) => {
            let sin6 = unsafe { &mut *ptr::from_mut(&mut dst).cast::<sockaddr_in6>() };
            sin6.sin6_len = size_of::<sockaddr_in6>()
                .try_into()
                .map_err(|e: TryFromIntError| unlikely_err(e.to_string()))?;
            sin6.sin6_family = AF_INET6
                .try_into()
                .map_err(|e: TryFromIntError| unlikely_err(e.to_string()))?;
            sin6.sin6_addr.s6_addr = ip.octets();
        }
    };

    // Prepare route message structure.
    let mut rtm: rt_msghdr = unsafe { mem::zeroed() };
    rtm.rtm_msglen = (size_of::<rt_msghdr>() + dst.ss_len as usize) // Length includes sockaddr
        .try_into()
        .map_err(|e: TryFromIntError| unlikely_err(e.to_string()))?;
    rtm.rtm_version = RTM_VERSION
        .try_into()
        .map_err(|e: TryFromIntError| unlikely_err(e.to_string()))?;
    rtm.rtm_type = RTM_GET
        .try_into()
        .map_err(|e: TryFromIntError| unlikely_err(e.to_string()))?;
    rtm.rtm_seq = fd.as_raw_fd(); // Abuse file descriptor as sequence number, since it's unique
    rtm.rtm_addrs = RTA_DST | RTA_IFP; // Query for destination and obtain interface info

    // Copy route message and destination `sockaddr` into message buffer.
    let mut msg: Vec<u8> = vec![0; rtm.rtm_msglen as usize];
    unsafe {
        ptr::copy_nonoverlapping(
            ptr::from_ref(&rtm).cast(),
            msg.as_mut_ptr(),
            size_of::<rt_msghdr>(),
        );
        ptr::copy_nonoverlapping(
            ptr::from_ref(&dst).cast(),
            msg.as_mut_ptr().add(size_of::<rt_msghdr>()),
            dst.ss_len as usize,
        );
    }

    // Send route message.
    let res = unsafe { write(fd.as_raw_fd(), msg.as_ptr().cast(), msg.len()) };
    if res == -1 {
        return Err(Error::last_os_error());
    }

    // Read route messages.
    let mut buf = vec![
        0u8;
        size_of::<rt_msghdr>() +
        // There will never be `RTAX_MAX` sockaddrs attached, but it's a safe upper bound.
         (RTAX_MAX as usize * size_of::<sockaddr_storage>())
    ];
    let rtm = loop {
        let len = unsafe { read(fd.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len()) };
        if len <= 0 {
            return Err(Error::last_os_error());
        }
        let rtm = unsafe { ptr::read_unaligned(buf.as_ptr().cast::<rt_msghdr>()) };
        if rtm.rtm_type
            == RTM_GET
                .try_into()
                .map_err(|e: TryFromIntError| unlikely_err(e.to_string()))?
            && rtm.rtm_pid == unsafe { getpid() }
            && rtm.rtm_seq == fd.as_raw_fd()
        {
            // This is the response we are looking for.
            break rtm;
        }
    };

    // Parse the route message for the interface name.
    let mut sa = unsafe { buf.as_ptr().add(size_of::<rt_msghdr>()) };
    for i in 0..RTAX_MAX {
        let sdl = unsafe { ptr::read_unaligned(sa.cast::<sockaddr_dl>()) };
        // Check if the address is present in the message
        if rtm.rtm_addrs & (1 << i) != 0 {
            // Check if the address is the interface address
            if i == RTAX_IFP {
                let name = unsafe {
                    slice::from_raw_parts(sdl.sdl_data.as_ptr().cast(), sdl.sdl_nlen as usize)
                };
                if let Ok(name) = str::from_utf8(name) {
                    // We have our interface name.
                    return Ok((name.to_string(), rtm.rtm_rmx.rmx_mtu as usize));
                }
            }
            let incr = next_item_aligned_by_four(sdl.sdl_len.into());
            sa = unsafe { sa.add(incr) };
        }
    }

    Err(default_err())
}
