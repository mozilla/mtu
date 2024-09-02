# MTU

A crate to return the maximum transmission unit (MTU) of the local network interface towards a given destination `SocketAddr`.

## Usage

This crate exports a single function

```rust
pub fn get_interface_mtu(remote: &SocketAddr) -> Result<usize, Error>
```

that returns the MTU of the local network interface towards the `remote` destination, or an `Error` when the MTU could not be determined. It supports both IPv4 and IPv6.

## Supported Platforms

* Linux
* macOS
* Windows

## Notes

The returned MTU may exceed the maximum IP packet size of 65,535 bytes on some platforms for some remote destinations. (For example, loopback destinations on Windows.)

## Contributing

We're happy to receive PRs that improve this crate. Please take a look at our [community guidelines](CODE_OF_CONDUCT.md) beforehand.
