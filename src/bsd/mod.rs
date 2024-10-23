// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::{
    ffi::CStr,
    io::Error,
    mem::{self, size_of},
    net::IpAddr,
    num::TryFromIntError,
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
    ptr, slice, str,
};

#[cfg(not(target_os = "openbsd"))]
use libc::RTA_IFP;
use libc::{
    freeifaddrs, getifaddrs, getpid, if_data, ifaddrs, read, sockaddr_dl, sockaddr_in,
    sockaddr_in6, sockaddr_storage, socket, write, AF_INET, AF_INET6, AF_LINK, AF_UNSPEC, PF_ROUTE,
    RTAX_IFA, RTAX_IFP, RTAX_MAX, RTA_DST, RTM_GET, RTM_VERSION, SOCK_RAW,
};

#[cfg(apple)]
use crate::bsd::apple::{rt_msghdr, ALIGN};
#[cfg(target_os = "freebsd")]
use crate::bsd::freebsd::{rt_msghdr, ALIGN};
#[cfg(target_os = "netbsd")]
use crate::bsd::netbsd::{rt_msghdr, ALIGN};
#[cfg(target_os = "openbsd")]
use crate::bsd::openbsd::{rt_msghdr, ALIGN};

#[cfg(apple)]
mod apple;

#[cfg(target_os = "freebsd")]
mod freebsd;

#[cfg(target_os = "netbsd")]
mod netbsd;

#[cfg(target_os = "openbsd")]
mod openbsd;

use crate::{aligned_by, default_err, unlikely_err};

fn get_mtu_for_interface(name: &str) -> Result<usize, Error> {
    let mut ifap: *mut ifaddrs = ptr::null_mut();
    if unsafe { getifaddrs(&mut ifap) } != 0 {
        return Err(Error::last_os_error());
    }
    let ifap = ifap; // Do not modify this pointer.
    let mut res = Err(default_err());

    let mut cursor = ifap;
    while !cursor.is_null() {
        let ifa = unsafe { &*cursor };
        if !ifa.ifa_addr.is_null() {
            let saddr = unsafe { &*ifa.ifa_addr };
            let ifa_name = unsafe { CStr::from_ptr(ifa.ifa_name).to_str().unwrap_or_default() };
            if libc::c_int::from(saddr.sa_family) == AF_LINK
                && !ifa.ifa_data.is_null()
                && ifa_name == name
            {
                let data = unsafe { &*(ifa.ifa_data as *const if_data) };
                if let Ok(mtu) = usize::try_from(data.ifi_mtu) {
                    res = Ok(mtu);
                    break;
                }
            }
        }
        cursor = ifa.ifa_next;
    }
    unsafe { freeifaddrs(ifap) };
    res
}

fn as_sockaddr_storage(ip: IpAddr) -> Result<sockaddr_storage, Error> {
    let mut dst: sockaddr_storage = unsafe { mem::zeroed() };
    match ip {
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
    Ok(dst)
}

pub fn interface_and_mtu_impl(remote: IpAddr) -> Result<(String, usize), Error> {
    // Open route socket.
    let fd = unsafe { socket(PF_ROUTE, SOCK_RAW, AF_UNSPEC) };
    if fd == -1 {
        return Err(Error::last_os_error());
    }
    let fd = unsafe { OwnedFd::from_raw_fd(fd) };

    // Prepare buffer with destination `sockaddr`.
    let dst = as_sockaddr_storage(remote)?;

    // Prepare route message structure.
    let mut query: rt_msghdr = unsafe { mem::zeroed() };
    query.rtm_msglen = (size_of::<rt_msghdr>() + aligned_by(dst.ss_len.into(), ALIGN)) // Length includes sockaddr
        .try_into()
        .map_err(|e: TryFromIntError| unlikely_err(e.to_string()))?;
    query.rtm_version = RTM_VERSION
        .try_into()
        .map_err(|e: TryFromIntError| unlikely_err(e.to_string()))?;
    query.rtm_type = RTM_GET
        .try_into()
        .map_err(|e: TryFromIntError| unlikely_err(e.to_string()))?;
    query.rtm_seq = fd.as_raw_fd(); // Abuse file descriptor as sequence number, since it's unique
    query.rtm_addrs = RTA_DST; // Query for destination
    #[cfg(not(target_os = "openbsd"))]
    {
        query.rtm_addrs |= RTA_IFP; // Obtain interface info
    }
    #[cfg(target_os = "openbsd")]
    {
        query.rtm_hdrlen = size_of::<rt_msghdr>()
            .try_into()
            .map_err(|e: TryFromIntError| unlikely_err(e.to_string()))?;
    }

    // Copy route message and destination `sockaddr` into message buffer.
    let mut msg: Vec<u8> = vec![0; query.rtm_msglen.into()];
    unsafe {
        ptr::copy_nonoverlapping(
            ptr::from_ref(&query).cast(),
            msg.as_mut_ptr(),
            size_of::<rt_msghdr>(),
        );
        ptr::copy_nonoverlapping(
            ptr::from_ref(&dst).cast(),
            msg.as_mut_ptr().add(size_of::<rt_msghdr>()),
            dst.ss_len.into(),
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
        let reply = unsafe { ptr::read_unaligned(buf.as_ptr().cast::<rt_msghdr>()) };
        if reply.rtm_version == query.rtm_version
            && reply.rtm_type == query.rtm_type
            && reply.rtm_pid == unsafe { getpid() }
            && reply.rtm_seq == query.rtm_seq
        {
            // This is the reply we are looking for.
            break reply;
        }
    };

    // Parse the route message for the interface name.
    let mut sa = unsafe { buf.as_ptr().add(size_of::<rt_msghdr>()) };
    for i in 0..RTAX_MAX {
        let sdl = unsafe { ptr::read_unaligned(sa.cast::<sockaddr_dl>()) };
        // Check if the address is present in the message
        if rtm.rtm_addrs & (1 << i) != 0 {
            // Check if the address is the interface address
            if (i == RTAX_IFP || i == RTAX_IFA)
                && sdl.sdl_family
                    == AF_LINK
                        .try_into()
                        .map_err(|e: TryFromIntError| unlikely_err(e.to_string()))?
                && sdl.sdl_nlen > 0
            {
                let if_name = unsafe {
                    slice::from_raw_parts(sdl.sdl_data.as_ptr().cast(), sdl.sdl_nlen.into())
                };
                if let Ok(if_name) = str::from_utf8(if_name) {
                    // We have our interface name.
                    // If rtm.rtm_rmx.rmx_mtu is 0, which can happen on OpenBSD and NetBSD, we need
                    // to get the MTU via different means based on the interface name.
                    let mtu = if rtm.rtm_rmx.rmx_mtu > 0 {
                        rtm.rtm_rmx
                            .rmx_mtu
                            .try_into()
                            .map_err(|e: TryFromIntError| unlikely_err(e.to_string()))?
                    } else {
                        get_mtu_for_interface(if_name)?
                    };
                    return Ok((if_name.to_string(), mtu));
                }
            }
            let incr = aligned_by(sdl.sdl_len.into(), ALIGN);
            sa = unsafe { sa.add(incr) };
        }
    }

    Err(default_err())
}
