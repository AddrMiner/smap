


#[cfg(not(windows))]
mod ipv6;
#[cfg(not(windows))]
mod ipv6_port;
#[cfg(not(windows))]
mod file_ipv6;
#[cfg(not(windows))]
mod file_ipv6_port;



#[cfg(not(windows))]
pub use ipv6::send_v6;

#[cfg(not(windows))]
pub use ipv6_port::send_v6_port;

// #[cfg(not(windows))]
// pub use file_ipv6::send_file_v6;

#[cfg(not(windows))]
pub use file_ipv6_port::send_file_v6_port;


#[cfg(windows)]
mod windows_pcap;


#[cfg(windows)]
pub use windows_pcap::ipv6::send_v6;

#[cfg(windows)]
pub use windows_pcap::ipv6_port::send_v6_port;

// #[cfg(windows)]
// pub use windows_pcap::file_ipv6::send_file_v6;

#[cfg(windows)]
pub use windows_pcap::file_ipv6_port::send_file_v6_port;