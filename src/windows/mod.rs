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

use crate::{
    default_err,
    windows::win_bindings::{
        if_indextoname, FreeMibTable, GetBestInterfaceEx, GetIpInterfaceTable, AF_INET, AF_INET6,
        AF_UNSPEC, IN6_ADDR, IN6_ADDR_0, IN_ADDR, IN_ADDR_0, MIB_IPINTERFACE_ROW,
        MIB_IPINTERFACE_TABLE, NO_ERROR, SOCKADDR, SOCKADDR_IN, SOCKADDR_IN6, SOCKADDR_INET,
    },
};

// Though the module includes `allow(clippy::all)`, that doesn't seem to affect some lints
#[allow(clippy::semicolon_if_nothing_returned, clippy::struct_field_names)]
mod win_bindings;

pub fn interface_and_mtu_impl(remote: IpAddr) -> Result<(String, usize), Error> {
    // Convert remote to Windows SOCKADDR_INET format.
    let mut dst: SOCKADDR_INET = unsafe { mem::zeroed() };
    match remote {
        IpAddr::V4(ip) => {
            let sin = unsafe { &mut *ptr::from_mut(&mut dst).cast::<SOCKADDR_IN>() };
            sin.sin_family = AF_INET;
            sin.sin_addr = IN_ADDR {
                S_un: IN_ADDR_0 {
                    S_addr: u32::to_be(ip.into()),
                },
            }
        }
        IpAddr::V6(ip) => {
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
        GetBestInterfaceEx(
            ptr::from_ref(&dst).cast::<SOCKADDR>(),
            ptr::from_mut(&mut idx),
        )
    };
    if res != 0 {
        return Err(Error::last_os_error());
    }

    // Get a list of all interfaces with associated metadata.
    let mut if_table: *mut MIB_IPINTERFACE_TABLE = ptr::null_mut();
    if unsafe { GetIpInterfaceTable(AF_UNSPEC, &mut if_table) } != NO_ERROR {
        return Err(Error::last_os_error());
    }
    let if_table = if_table; // Do not modify this pointer.
    let ifaces = unsafe {
        slice::from_raw_parts::<MIB_IPINTERFACE_ROW>(
            &(*if_table).Table[0],
            (*if_table).NumEntries as usize,
        )
    };

    // Find the local interface matching `idx`.
    for iface in ifaces {
        if iface.InterfaceIndex == idx {
            if let Ok(mtu) = iface.NlMtu.try_into() {
                let mut name = [0u8; 256]; // IF_NAMESIZE not available?
                if unsafe { !if_indextoname(iface.InterfaceIndex, &mut name).is_null() } {
                    if let Ok(name) = CStr::from_bytes_until_nul(&name) {
                        if let Ok(name) = name.to_str() {
                            // We found our interface information.
                            unsafe { FreeMibTable(if_table as *const c_void) };
                            return Ok((name.to_string(), mtu));
                        }
                    }
                }
            }
            break;
        }
    }

    unsafe { FreeMibTable(if_table as *const c_void) };
    Err(default_err())
}
