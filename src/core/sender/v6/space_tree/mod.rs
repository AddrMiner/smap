


#[cfg(windows)]
mod windows_pcap;

#[cfg(not(windows))]
mod scan_code_v6;


#[cfg(windows)]
pub use windows_pcap::scan_code_v6::send_v6_vec;


#[cfg(not(windows))]
pub use scan_code_v6::send_v6_vec;
