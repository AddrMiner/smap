use crate::tools::net_handle::net_interface::mac_addr::MacAddress;

#[allow(dead_code)]
pub struct EthernetPacket {

    destination:MacAddress,
    source:MacAddress,
    ethernet_type:u16

}


#[allow(dead_code)]
impl EthernetPacket {


    #[allow(dead_code)]
    pub fn new(d:&[u8]) -> Self {

        Self {
            destination: MacAddress::new([d[0], d[1], d[2], d[3], d[4], d[5]]),
            source: MacAddress::new([d[6], d[7], d[8], d[9], d[10], d[11]]),
            ethernet_type: ((d[12] as u16) << 8) | (d[13] as u16),
        }


    }




}