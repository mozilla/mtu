// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

const BINDINGS: &str = "bindings.rs";

#[cfg(feature = "gecko")]
fn clang_args() -> Vec<String> {
    use mozbuild::TOPOBJDIR;

    let flags_path = TOPOBJDIR.join("netwerk/socket/neqo/extra-bindgen-flags");
    println!("cargo:rerun-if-changed={}", flags_path.to_str().unwrap());

    let mut flags: Vec<String> = std::fs::read_to_string(flags_path)
        .expect("Failed to read extra-bindgen-flags file")
        .split_whitespace()
        .map(std::borrow::ToOwned::to_owned)
        .collect();

    flags.push(String::from("-include"));
    flags.push(
        TOPOBJDIR
            .join("dist")
            .join("include")
            .join("mozilla-config.h")
            .to_str()
            .unwrap()
            .to_string(),
    );
    flags
}

#[cfg(not(feature = "gecko"))]
const fn clang_args() -> Vec<String> {
    Vec::new()
}

#[cfg(not(windows))]
fn bindgen() {
    #[cfg(target_os = "linux")]
    let bindings = bindgen::Builder::default()
        .header_contents("rtnetlink.h", "#include <linux/rtnetlink.h>")
        // Only generate bindings for the following types
        .allowlist_type("rtattr|rtmsg|ifinfomsg|nlmsghdr");
    #[cfg(not(target_os = "linux"))]
    let bindings = bindgen::Builder::default()
        .header_contents(
            "route.h",
            #[cfg(any(target_os = "freebsd", target_os = "openbsd"))]
            "#include <sys/types.h>\n#include <sys/socket.h>\n#include <net/route.h>",
            #[cfg(not(any(target_os = "freebsd", target_os = "openbsd")))]
            "#include <net/route.h>",
        )
        // Only generate bindings for the following types
        .allowlist_type("rt_msghdr|rt_metrics");
    let bindings = bindings
        .clang_args(clang_args())
        // Tell cargo to invalidate the built crate whenever any of the
        // included header files changed.
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
        // Constants should be generated as &CStr instead of &[u8].
        .generate_cstr(true)
        // Always emit explicit padding fields.
        .explicit_padding(true)
        // Default trait should be derived when possible
        .derive_default(true)
        // Finish the builder and generate the bindings.
        .generate()
        // Unwrap the Result and panic on failure.
        .expect("Unable to generate bindings");

    // Write the bindings to the $OUT_DIR/$BINDINGS file.
    let out_path = std::path::PathBuf::from(std::env::var("OUT_DIR").unwrap()).join(BINDINGS);
    bindings
        .write_to_file(out_path.clone())
        .expect("Couldn't write bindings!");
    println!("cargo:rustc-env=BINDINGS={}", out_path.display());
}

#[cfg(windows)]
fn bindgen() {
    let out_path = std::path::PathBuf::from(std::env::var("OUT_DIR").unwrap()).join(BINDINGS);
    windows_bindgen::bindgen([
        "--out",
        out_path.to_str().unwrap(),
        "--config",
        "flatten",
        "no-inner-attributes",
        "minimal",
        "--filter",
        "Windows.Win32.Foundation.NO_ERROR",
        "Windows.Win32.Networking.WinSock.AF_INET",
        "Windows.Win32.Networking.WinSock.AF_INET6",
        "Windows.Win32.Networking.WinSock.AF_UNSPEC",
        "Windows.Win32.Networking.WinSock.SOCKADDR_INET",
        "Windows.Win32.NetworkManagement.IpHelper.FreeMibTable",
        "Windows.Win32.NetworkManagement.IpHelper.GetBestInterfaceEx",
        "Windows.Win32.NetworkManagement.IpHelper.GetIpInterfaceTable",
        "Windows.Win32.NetworkManagement.IpHelper.if_indextoname",
        "Windows.Win32.NetworkManagement.IpHelper.MIB_IPINTERFACE_ROW",
        "Windows.Win32.NetworkManagement.Ndis.IF_MAX_STRING_SIZE",
    ])
    .expect("Couldn't write bindings!");
    println!("cargo:rustc-env=BINDINGS={}", out_path.display());
}

fn main() {
    // Setup cfg aliases
    cfg_aliases::cfg_aliases! {
        // Platforms
        apple: {
            any(
                target_os = "macos",
                target_os = "ios",
                target_os = "tvos",
                target_os = "visionos"
            )
        },
        bsd: {
            any(
                target_os = "freebsd",
                target_os = "openbsd",
                target_os = "netbsd"
            )
        }
    }
    bindgen();
}
