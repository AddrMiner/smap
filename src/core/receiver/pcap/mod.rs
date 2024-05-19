pub mod init;
pub mod base;
pub mod pmap;
mod topo;
mod space_tree;

use pcap::{Active, Capture};

pub struct PcapReceiver {
    active_capture:Capture<Active>,     // 打开状态下的 捕获
    data_link_len:usize,
}

use pcap::{Packet, PacketCodec, PacketHeader};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PacketOwned {
    pub header: PacketHeader,
    pub data: Box<[u8]>,
}


struct Codec;

impl PacketCodec for Codec {
    type Item = PacketOwned;

    fn decode(&mut self, packet: Packet) -> Self::Item {
        PacketOwned {
            header: *packet.header,
            data: packet.data.into(),
        }
    }
}