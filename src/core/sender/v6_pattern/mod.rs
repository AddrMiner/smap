


#[cfg(not(windows))]
mod cycle_group;

#[cfg(not(windows))]
pub use cycle_group::send_cycle_group_v6_pattern;

#[cfg(windows)]
mod windows_pcap;


#[cfg(windows)]
pub use windows_pcap::cycle_group::send_cycle_group_v6_pattern;