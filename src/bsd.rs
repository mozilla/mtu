// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use core::str;
use std::{ffi::c_void, io::Error, mem, mem::size_of, net::IpAddr, ptr};

use libc::{
    close, getpid, read, rt_msghdr, sockaddr_dl, sockaddr_in, sockaddr_in6, sockaddr_storage,
    socket, write, AF_INET, AF_INET6, PF_ROUTE, RTAX_IFP, RTAX_MAX, RTA_DST, RTA_IFP, RTM_GET,
    RTM_VERSION, SOCK_RAW,
};

use crate::default_err;

pub fn interface_and_mtu_impl(remote: IpAddr) -> Result<(String, usize), Error> {
    // Open route socket.
    let fd = unsafe { socket(PF_ROUTE, SOCK_RAW, 0) };
    if fd == -1 {
        eprintln!("socket error: {}", Error::last_os_error());
        return Err(Error::last_os_error());
    }

    // Prepare buffer with destination `sockaddr`.
    #[allow(clippy::cast_possible_truncation)]
    let (remote, len) = match remote {
        IpAddr::V4(ip) => {
            let mut sin: sockaddr_in = unsafe { mem::zeroed() };
            sin.sin_len = size_of::<sockaddr_in>() as u8;
            sin.sin_family = AF_INET as u8;
            sin.sin_addr.s_addr = u32::from_ne_bytes(ip.octets());
            (
                ptr::from_ref::<sockaddr_in>(&sin).cast::<u8>(),
                size_of::<sockaddr_in>(),
            )
        }
        IpAddr::V6(ip) => {
            let mut sin6: sockaddr_in6 = unsafe { mem::zeroed() };
            sin6.sin6_len = size_of::<sockaddr_in6>() as u8;
            sin6.sin6_family = AF_INET6 as u8;
            sin6.sin6_addr.s6_addr = ip.octets();
            (
                ptr::from_ref::<sockaddr_in6>(&sin6).cast::<u8>(),
                size_of::<sockaddr_in6>(),
            )
        }
    };

    // Prepare route message structure.
    let mut rtm: rt_msghdr = unsafe { mem::zeroed() };
    #[allow(clippy::cast_possible_truncation)]
    {
        rtm.rtm_msglen = (size_of::<rt_msghdr>() + len) as u16; // Length includes sockaddr
        rtm.rtm_version = RTM_VERSION as u8;
        rtm.rtm_type = RTM_GET as u8;
    }
    rtm.rtm_seq = fd; // Abuse file descriptor as sequence number, since it's unique
    rtm.rtm_addrs = RTA_DST | RTA_IFP; // Query for destination and obtain interface info

    // Copy route message and destination `sockaddr` into message buffer.
    let mut msg: Vec<u8> = vec![0; rtm.rtm_msglen as usize];
    unsafe {
        ptr::copy_nonoverlapping(
            ptr::from_ref::<rt_msghdr>(&rtm).cast::<u8>(),
            msg.as_mut_ptr(),
            size_of::<rt_msghdr>(),
        );
        ptr::copy_nonoverlapping(remote, msg.as_mut_ptr().add(size_of::<rt_msghdr>()), len);
    }

    // Send route message.
    let res = unsafe { write(fd, msg.as_ptr().cast::<c_void>(), msg.len()) };
    if res == -1 {
        eprintln!("write error: {}", Error::last_os_error());
        unsafe { close(fd) };
        return Err(Error::last_os_error());
    }

    // Read route messages.
    let mut buf = vec![
        0u8;
        size_of::<rt_msghdr>() +
        // There will never be `RTAX_MAX` sockaddrs, but it's a safe upper bound
         (RTAX_MAX as usize * size_of::<sockaddr_storage>())
    ];
    let rtm = loop {
        let len = unsafe { read(fd, buf.as_mut_ptr().cast::<c_void>(), buf.len()) };
        if len <= 0 {
            eprintln!("read error: {}", Error::last_os_error());
            unsafe { close(fd) };
            return Err(Error::last_os_error());
        }
        let rtm = unsafe { ptr::read_unaligned(buf.as_ptr().cast::<rt_msghdr>()) };
        #[allow(clippy::cast_possible_truncation)]
        if rtm.rtm_type == RTM_GET as u8 && rtm.rtm_pid == unsafe { getpid() } && rtm.rtm_seq == fd
        {
            // This is the response we are looking for.
            break rtm;
        }
    };

    // Close the route socket.
    unsafe { close(fd) };

    // Parse the route message for the interface name.
    let mut sa = unsafe { buf.as_ptr().add(size_of::<rt_msghdr>()) };
    for i in 0..RTAX_MAX {
        let sdl = unsafe { ptr::read_unaligned(sa.cast::<sockaddr_dl>()) };
        // Check if the address is present in the message
        if rtm.rtm_addrs & (1 << i) != 0 {
            // Check if the address is the interface address
            if i == RTAX_IFP {
                if let Ok(name) = unsafe {
                    str::from_utf8(std::slice::from_raw_parts(
                        sdl.sdl_data.as_ptr().cast::<u8>(),
                        sdl.sdl_nlen as usize,
                    ))
                } {
                    // We have our interface name.
                    return Ok((name.to_string(), rtm.rtm_rmx.rmx_mtu as usize));
                }
            }
            // Advance to the next address. The length is always a multiple of 4, so we need to do
            // some awkward manipulation.
            sa = unsafe {
                sa.add(if sdl.sdl_len == 0 {
                    4
                } else {
                    ((sdl.sdl_len - 1) | 3) + 1
                } as usize)
            };
        }
    }

    Err(default_err())
}
