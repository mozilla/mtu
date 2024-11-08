// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::{
    io::{Error, Read, Write},
    num::TryFromIntError,
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
};

use libc::{fsync, read, socket, write, SOCK_RAW};

use crate::unlikely_err;

pub struct RouteSocket(OwnedFd);

impl RouteSocket {
    pub fn new(domain: libc::c_int, protocol: libc::c_int) -> Result<Self, Error> {
        let fd = unsafe { socket(domain, SOCK_RAW, protocol) };
        if fd == -1 {
            return Err(Error::last_os_error());
        }
        Ok(Self(unsafe { OwnedFd::from_raw_fd(fd) }))
    }
}

impl AsRawFd for RouteSocket {
    fn as_raw_fd(&self) -> i32 {
        self.0.as_raw_fd()
    }
}

fn check_result(res: isize) -> Result<usize, Error> {
    if res == -1 {
        Err(Error::last_os_error())
    } else {
        Ok(res
            .try_into()
            .map_err(|e: TryFromIntError| unlikely_err(e.to_string()))?)
    }
}

impl Write for RouteSocket {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let res = unsafe { write(self.as_raw_fd(), buf.as_ptr().cast(), buf.len()) };
        check_result(res)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        let res = unsafe { fsync(self.as_raw_fd()) };
        check_result(res as isize).and(Ok(()))
    }
}

impl Read for RouteSocket {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        // If we've written a well-formed message into the kernel via `write`, we should be able to
        // read a well-formed message back out, and not block.
        let res = unsafe { read(self.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len()) };
        check_result(res)
    }
}
