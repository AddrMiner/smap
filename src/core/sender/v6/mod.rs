


#[cfg(not(windows))]
mod cycle_group;

#[cfg(not(windows))]
mod file_reader;

#[cfg(not(windows))]
pub use cycle_group::send_cycle_group_v6;

#[cfg(not(windows))]
pub use file_reader::send_file_reader_v6;

#[cfg(windows)]
mod windows_pcap;

#[cfg(windows)]
pub use windows_pcap::cycle_group::send_cycle_group_v6;


#[cfg(windows)]
pub use windows_pcap::file_reader::send_file_reader_v6;