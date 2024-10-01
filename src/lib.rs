// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::{
    io::{Error, ErrorKind},
    net::IpAddr,
};

#[cfg(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "openbsd",
))]
use bsd::interface_and_mtu_impl;

#[cfg(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "openbsd",
))]
mod bsd;

#[cfg(windows)]
mod win_bindings;

/// Prepare a default error.
fn default_err() -> Error {
    Error::new(ErrorKind::NotFound, "Local interface MTU not found")
}

/// Return the name and maximum transmission unit (MTU) of a local network interface.
///
/// Given a remote [`IpAddr`], return the name and maximum transmission unit (MTU) of the local
/// network interface towards the remote destination.
///
/// The returned MTU may exceed the maximum IP packet size of 65,535 bytes on some
/// platforms for some remote destinations. (For example, loopback destinations on
/// Windows.)
///
/// The returned interface name is obtained from the operating system.
///
/// # Examples
///
/// ```
/// let remote = "127.0.0.1".parse().unwrap();
/// let (name, mtu) = mtu::interface_and_mtu(remote).unwrap();
/// println!("MTU towards {remote:?} is {mtu} on {name}");
/// ```
///
/// # Errors
///
/// This function returns an error if the local interface MTU cannot be determined.
// #[allow(clippy::missing_panics_doc, clippy::too_many_lines)]
pub fn interface_and_mtu(remote: IpAddr) -> Result<(String, usize), Error> {
    interface_and_mtu_impl(remote)
}

#[cfg(test)]
mod test {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    use crate::interface_and_mtu;

    #[derive(Debug)]
    struct NameMtu<'a>(Option<&'a str>, usize);

    impl PartialEq<NameMtu<'_>> for (String, usize) {
        fn eq(&self, other: &NameMtu<'_>) -> bool {
            other.0.map_or(true, |name| name == self.0) && other.1 == self.1
        }
    }

    #[cfg(any(target_os = "macos", target_os = "freebsd",))]
    const LOOPBACK: NameMtu = NameMtu(Some("lo0"), 16_384);
    #[cfg(target_os = "linux")]
    const LOOPBACK: NameMtu = NameMtu(Some("lo"), 65_536);
    #[cfg(target_os = "windows")]
    const LOOPBACK: NameMtu = NameMtu(Some("loopback_0"), 4_294_967_295);
    #[cfg(target_os = "openbsd")]
    const LOOPBACK: NameMtu = NameMtu(Some("lo0"), 32_768);
    #[cfg(target_os = "netbsd")]
    const LOOPBACK: NameMtu = NameMtu(Some("lo0"), 33_624);

    // Non-loopback interface names are unpredictable, so we only check the MTU.
    const INET: NameMtu = NameMtu(None, 1_500);

    #[test]
    fn loopback_v4() {
        assert_eq!(
            interface_and_mtu(IpAddr::V4(Ipv4Addr::LOCALHOST)).unwrap(),
            LOOPBACK
        );
    }

    #[test]
    fn loopback_v6() {
        assert_eq!(
            interface_and_mtu(IpAddr::V6(Ipv6Addr::LOCALHOST)).unwrap(),
            LOOPBACK
        );
    }

    #[test]
    fn inet_v4() {
        // cloudflare.com
        assert_eq!(
            interface_and_mtu(IpAddr::V4(Ipv4Addr::new(104, 16, 132, 229))).unwrap(),
            INET
        );
    }

    #[test]
    fn inet_v6() {
        // cloudflare.com
        assert_eq!(
            interface_and_mtu(IpAddr::V6(Ipv6Addr::new(
                0x26, 0x06, 0x47, 0x00, 0x68, 0x10, 0x84, 0xe5,
            )))
            .unwrap(),
            INET
        );
    }
}
