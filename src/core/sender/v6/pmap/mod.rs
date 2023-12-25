

#[cfg(not(windows))]
mod full_scan;

#[cfg(not(windows))]
mod recommend_new_scan;

#[cfg(not(windows))]
mod recommend_scan;

#[cfg(windows)]
mod windows_pcap;


#[cfg(windows)]
pub use windows_pcap::full_scan::pmap_full_scan_send_v6;

#[cfg(windows)]
pub use windows_pcap::recommend_scan::pmap_recommend_scan_send_v6_port;

#[cfg(windows)]
pub use windows_pcap::recommend_new_scan::pmap_recommend_new_scan_send_v6_port;


#[cfg(not(windows))]
pub use full_scan::pmap_full_scan_send_v6;

#[cfg(not(windows))]
pub use recommend_new_scan::pmap_recommend_new_scan_send_v6_port;

#[cfg(not(windows))]
pub use recommend_scan::pmap_recommend_scan_send_v6_port;