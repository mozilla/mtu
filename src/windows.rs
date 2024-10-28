// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::{
    ffi::{c_void, CStr},
    io::Error,
    mem,
    net::IpAddr,
    ptr, slice,
};

use bindings::{
    if_indextoname, FreeMibTable, GetBestInterfaceEx, GetIpInterfaceTable, AF_INET, AF_INET6,
    AF_UNSPEC, IN6_ADDR, IN6_ADDR_0, IN_ADDR, IN_ADDR_0, MIB_IPINTERFACE_ROW,
    MIB_IPINTERFACE_TABLE, NO_ERROR, SOCKADDR, SOCKADDR_IN, SOCKADDR_IN6, SOCKADDR_INET,
};

use crate::default_err;

#[allow(non_camel_case_types, non_snake_case)]
mod bindings {
    include!(env!("BINDINGS"));
}

struct MibTablePtr(*mut MIB_IPINTERFACE_TABLE);

impl Drop for MibTablePtr {
    fn drop(&mut self) {
        // Free the memory allocated by GetIpInterfaceTable.
        unsafe { FreeMibTable(self.0 as *const c_void) };
    }
}

pub fn interface_and_mtu_impl(remote: IpAddr) -> Result<(String, usize), Error> {
    // Convert remote to Windows SOCKADDR_INET format. The SOCKADDR_INET union contains an IPv4 or
    // an IPv6 address. We allocate and zero-initialize it here.
    //
    // See https://learn.microsoft.com/en-us/windows/win32/api/ws2ipdef/ns-ws2ipdef-sockaddr_inet

    let mut dst: SOCKADDR_INET = unsafe { mem::zeroed() };
    match remote {
        IpAddr::V4(ip) => {
            // Initialize the `SOCKADDR_IN` variant of `SOCKADDR_INET` based on `ip`.
            let sin = unsafe { &mut *ptr::from_mut(&mut dst).cast::<SOCKADDR_IN>() };
            sin.sin_family = AF_INET;
            sin.sin_addr = IN_ADDR {
                S_un: IN_ADDR_0 {
                    S_addr: u32::to_be(ip.into()),
                },
            }
        }
        IpAddr::V6(ip) => {
            // Initialize the `SOCKADDR_IN6` variant of `SOCKADDR_INET` based on `ip`.
            let sin6 = unsafe { &mut *ptr::from_mut(&mut dst).cast::<SOCKADDR_IN6>() };
            sin6.sin6_family = AF_INET6;
            sin6.sin6_addr = IN6_ADDR {
                u: IN6_ADDR_0 { Byte: ip.octets() },
            };
        }
    }

    // Get the interface index of the best outbound interface towards `dst`.
    let mut idx = 0;
    let res = unsafe {
        // We're now casting `&dst` to a `SOCKADDR` pointer. This is OK based on
        // https://learn.microsoft.com/en-us/windows/win32/winsock/sockaddr-2.
        // With that, we call `GetBestInterfaceEx` to get the interface index into `idx`.
        // See https://learn.microsoft.com/en-us/windows/win32/api/iphlpapi/nf-iphlpapi-getbestinterfaceex
        GetBestInterfaceEx(
            ptr::from_ref(&dst).cast::<SOCKADDR>(),
            ptr::from_mut(&mut idx),
        )
    };
    if res != 0 {
        return Err(Error::last_os_error());
    }

    // Get a list of all interfaces with associated metadata.
    let mut if_table = MibTablePtr(ptr::null_mut());
    // GetIpInterfaceTable allocates memory, which MibTablePtr::drop will free.
    if unsafe { GetIpInterfaceTable(AF_UNSPEC, ptr::from_mut(&mut if_table.0)) } != NO_ERROR {
        return Err(Error::last_os_error());
    }
    // Make a slice
    let ifaces = unsafe {
        slice::from_raw_parts::<MIB_IPINTERFACE_ROW>(
            &(*if_table.0).Table[0],
            (*if_table.0).NumEntries as usize,
        )
    };

    // Find the local interface matching `idx`.
    for iface in ifaces {
        if iface.InterfaceIndex == idx {
            if let Ok(mtu) = iface.NlMtu.try_into() {
                let mut name = [0u8; 256]; // IF_NAMESIZE not available?
                                           // if_indextoname writes into the provided buffer.
                if unsafe { !if_indextoname(iface.InterfaceIndex, &mut name).is_null() } {
                    if let Ok(name) = CStr::from_bytes_until_nul(&name) {
                        if let Ok(name) = name.to_str() {
                            // We found our interface information.
                            return Ok((name.to_string(), mtu));
                        }
                    }
                }
            }
            break;
        }
    }
    Err(default_err())
}
