#![cfg(windows)]

use std::fs;

#[test]
fn codegen_windows_bindings() {
    let existing = fs::read_to_string(TARGET).unwrap_or_default();
    windows_bindgen::bindgen([
        "--out",
        TARGET,
        "--config",
        "flatten",
        "--filter",
        "Windows.Win32.Foundation.NO_ERROR",
        "Windows.Win32.NetworkManagement.IpHelper.FreeMibTable",
        "Windows.Win32.NetworkManagement.IpHelper.GetIpInterfaceTable",
        "Windows.Win32.NetworkManagement.IpHelper.GetUnicastIpAddressTable",
        "Windows.Win32.NetworkManagement.IpHelper.MIB_IPINTERFACE_ROW",
        "Windows.Win32.NetworkManagement.IpHelper.MIB_IPINTERFACE_TABLE",
        "Windows.Win32.NetworkManagement.IpHelper.MIB_UNICASTIPADDRESS_ROW",
        "Windows.Win32.NetworkManagement.IpHelper.MIB_UNICASTIPADDRESS_TABLE",
        "Windows.Win32.NetworkManagement.IpHelper.if_indextoname",
        "Windows.Win32.Networking.WinSock.AF_INET",
        "Windows.Win32.Networking.WinSock.AF_INET6",
        "Windows.Win32.Networking.WinSock.AF_UNSPEC",
    ])
    .unwrap();

    // Check the output is the same as before.
    // Depending on the git configuration the file may have been checked out with `\r\n` newlines or
    // with `\n`. Compare line-by-line to ignore this difference.
    let new = fs::read_to_string(TARGET).unwrap();
    if !new.lines().eq(existing.lines()) {
        println!("{new}");
        panic!("generated file `{TARGET}` is changed");
    }
}

const TARGET: &str = "src/win_bindings.rs";
