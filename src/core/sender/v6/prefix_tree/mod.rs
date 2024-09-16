

#[cfg(windows)]
mod windows_pcap;


#[cfg(not(windows))]
mod scan_prefixes_v6;


#[cfg(windows)]
pub use windows_pcap::scan_prefixes_v6::send_prefixes_v6;


#[cfg(not(windows))]
pub use scan_prefixes_v6::send_prefixes_v6;


