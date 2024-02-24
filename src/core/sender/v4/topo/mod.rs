#[cfg(not(windows))]
mod pre_scan;
#[cfg(not(windows))]
mod topo_scan;

#[cfg(windows)]
mod windows_pcap;


#[cfg(not(windows))]
pub use pre_scan::topo_pre_scan_send_v4;


#[cfg(not(windows))]
pub use topo_scan::topo_scan_send_v4;


#[cfg(windows)]
pub use windows_pcap::pre_scan::topo_pre_scan_send_v4;

#[cfg(windows)]
pub use windows_pcap::topo_scan::topo_scan_send_v4;