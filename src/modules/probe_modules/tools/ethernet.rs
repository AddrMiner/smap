use crate::tools::net_handle::net_interface::mac_addr::MacAddress;

pub fn make_ethernet_header(buf:&mut Vec<u8>, local_mac: &MacAddress, gateway_mac: &MacAddress, ethernet_type:u16) {

    //  填充以太网首部字段  14字节
    //  以太网首部  [  目标MAC地址 (6字节)  |  源MAC地址 (6字节) | 类型 (2字节)  ]

    // 将网关地址作为目的地址   注意目的地址在前
    buf.extend(gateway_mac.bytes);

    // 将本地地址作为源地址
    buf.extend(local_mac.bytes);

    // 以太网类型字段中的标识
    buf.extend(ethernet_type.to_be_bytes());
    
}