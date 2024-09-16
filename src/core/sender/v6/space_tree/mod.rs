


#[cfg(windows)]
mod windows_pcap;

#[cfg(not(windows))]
mod scan_u16code_v6;

#[cfg(not(windows))]
mod scan_u32code_v6;

#[cfg(windows)]
pub use windows_pcap::scan_u16code_v6::send_v6_u16code_vec;


#[cfg(windows)]
pub use windows_pcap::scan_u32code_v6::send_v6_u32code_vec;

#[cfg(not(windows))]
pub use scan_u16code_v6::send_v6_u16code_vec;

#[cfg(not(windows))]
pub use scan_u32code_v6::send_v6_u32code_vec;

