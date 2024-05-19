


#[cfg(not(windows))]
mod ipv4;
#[cfg(not(windows))]
mod ipv4_port;
#[cfg(not(windows))]
mod file_ipv4;
#[cfg(not(windows))]
mod file_ipv4_port;



#[cfg(not(windows))]
pub use ipv4::send_v4;

#[cfg(not(windows))]
pub use ipv4_port::send_v4_port;

// #[cfg(not(windows))]
// pub use file_ipv4::send_file_v4;

#[cfg(not(windows))]
pub use file_ipv4_port::send_file_v4_port;


#[cfg(windows)]
mod windows_pcap;


#[cfg(windows)]
pub use windows_pcap::ipv4::send_v4;

#[cfg(windows)]
pub use windows_pcap::ipv4_port::send_v4_port;

// #[cfg(windows)]
// pub use windows_pcap::file_ipv4::send_file_v4;

#[cfg(windows)]
pub use windows_pcap::file_ipv4_port::send_file_v4_port;

