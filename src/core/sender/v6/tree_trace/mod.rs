

#[cfg(not(windows))]
mod scan_prefixes_v6_;

#[cfg(windows)]
mod windows_pcap;


#[cfg(windows)]
pub use windows_pcap::scan_prefixes_v6_::send_prefixes_v6_2;

#[cfg(not(windows))]
pub use scan_prefixes_v6_::send_prefixes_v6_2;