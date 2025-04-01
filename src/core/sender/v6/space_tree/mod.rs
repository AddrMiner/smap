


#[cfg(windows)]
mod windows_pcap;

#[cfg(not(windows))]
mod scan_code_v6;


#[cfg(not(windows))]
mod scan_code_v6_port;

#[cfg(windows)]
pub use windows_pcap::scan_code_v6::send_v6_code_vec;



#[cfg(windows)]
pub use windows_pcap::scan_code_v6_port::send_v6_code_port_vec;


#[cfg(not(windows))]
pub use scan_code_v6::send_v6_code_vec;


#[cfg(not(windows))]
pub use scan_code_v6_port::send_v6_code_port_vec;
