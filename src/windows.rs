// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::{
    ffi::{c_void, CStr},
    io::{Error, ErrorKind, Result},
    net::IpAddr,
    ptr, slice,
};

use crate::default_err;

#[allow(
    non_camel_case_types,
    non_snake_case,
    clippy::semicolon_if_nothing_returned,
    clippy::missing_transmute_annotations,
    clippy::upper_case_acronyms,
    clippy::struct_field_names
)]
mod bindings {
    include!(env!("BINDINGS"));
}

use bindings::{
    if_indextoname, FreeMibTable, GetBestInterfaceEx, GetIpInterfaceTable, AF_INET, AF_INET6,
    AF_UNSPEC, IF_MAX_STRING_SIZE, IN6_ADDR, IN6_ADDR_0, IN_ADDR, IN_ADDR_0, MIB_IPINTERFACE_ROW,
    MIB_IPINTERFACE_TABLE, NO_ERROR, SOCKADDR, SOCKADDR_IN, SOCKADDR_IN6, SOCKADDR_INET,
};

struct MibTablePtr(*mut MIB_IPINTERFACE_TABLE);

impl Default for MibTablePtr {
    fn default() -> Self {
        Self(ptr::null_mut())
    }
}

impl Drop for MibTablePtr {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // Free the memory allocated by GetIpInterfaceTable.
            unsafe { FreeMibTable(self.0 as *const c_void) };
        }
    }
}

pub fn interface_and_mtu_impl(remote: IpAddr) -> Result<(String, usize)> {
    // Convert remote to Windows SOCKADDR_INET format. The SOCKADDR_INET union contains an IPv4 or
    // an IPv6 address.
    //
    // See https://learn.microsoft.com/en-us/windows/win32/api/ws2ipdef/ns-ws2ipdef-sockaddr_inet
    let dst = match remote {
        IpAddr::V4(ip) => {
            // Initialize the `SOCKADDR_IN` variant of `SOCKADDR_INET` based on `ip`.
            SOCKADDR_INET {
                Ipv4: SOCKADDR_IN {
                    sin_family: AF_INET,
                    sin_addr: IN_ADDR {
                        S_un: IN_ADDR_0 {
                            S_addr: u32::to_be(ip.into()),
                        },
                    },
                    ..Default::default()
                },
            }
        }
        IpAddr::V6(ip) => {
            // Initialize the `SOCKADDR_IN6` variant of `SOCKADDR_INET` based on `ip`.
            SOCKADDR_INET {
                Ipv6: SOCKADDR_IN6 {
                    sin6_family: AF_INET6,
                    sin6_addr: IN6_ADDR {
                        u: IN6_ADDR_0 { Byte: ip.octets() },
                    },
                    ..Default::default()
                },
            }
        }
    };

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
    let mut if_table = MibTablePtr::default();
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
            // Get the MTU.
            let mtu: usize = iface.NlMtu.try_into().or(Err(default_err()))?;
            // Get the interface name.
            let mut interfacename = [0u8; IF_MAX_STRING_SIZE as usize];
            // if_indextoname writes into the provided buffer.
            if unsafe { if_indextoname(iface.InterfaceIndex, &mut interfacename).is_null() } {
                return Err(default_err());
            }
            // Convert the interface name to a Rust string.
            let name = CStr::from_bytes_until_nul(interfacename.as_ref())
                .or(Err(default_err()))?
                .to_str()
                .map_err(|err| Error::new(ErrorKind::Other, err))?
                .to_string();
            // We found our interface information.
            return Ok((name, mtu));
        }
    }
    Err(default_err())
}