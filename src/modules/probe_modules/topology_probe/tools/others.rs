

/// 范围: 0-65534
#[inline]
pub fn get_dest_port(default_dest_port:u16, dest_port_offset:u16) -> u16 {
    (default_dest_port + dest_port_offset) % 65535
}