

#[cfg(any(
target_os = "freebsd",
target_os = "netbsd",
target_os = "illumos",
target_os = "solaris",
target_os = "openbsd",
target_os = "macos",
target_os = "ios"))]
mod bsd;

#[cfg(target_os = "linux")]
mod linux;

#[cfg(windows)]
mod windows;

#[cfg(any(
target_os = "freebsd",
target_os = "netbsd",
target_os = "illumos",
target_os = "solaris",
target_os = "openbsd",
target_os = "macos",
target_os = "ios"))]
pub use bsd::packet_sender::PacketSender;

#[cfg(target_os = "linux")]
pub use linux::packet_sender::PacketSender;

#[cfg(windows)]
pub use windows::pcap::PcapSender;