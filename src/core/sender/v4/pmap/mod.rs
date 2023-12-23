

#[cfg(not(windows))]
mod full_scan;


#[cfg(windows)]
mod windows_pcap;


#[cfg(windows)]
pub use windows_pcap::full_scan::pmap_full_scan_send_v4;

#[cfg(windows)]
pub use windows_pcap::recommend_scan::pmap_recommend_scan_send_v4_port;