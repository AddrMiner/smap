use std::process::exit;
use log::{error, warn};
use pcap::{Active, Capture};
use pcap::sendqueue::SendQueue;
use crate::SYS;


#[cfg(windows)]
pub struct PcapSender {}

#[cfg(windows)]
impl PcapSender {

    pub fn init(interface_name:&str, batch_size:u64, max_packet_length:usize) -> (Capture<Active>, SendQueue, u32){

        // 7 byte MAC preamble, 1 byte Start frame, 4 byte CRC, 12 byte inter-frame gap
        let mut pkt_len = (max_packet_length as u64) + 24;
        if pkt_len < 84 {
            // 如果小于 以太网帧 的最小大小，则调整计算的长度
            pkt_len = 84;
        }

        // 计算最大字节数量
        let bytes_num = batch_size * pkt_len;

        // 重新计算后的批次大小
        let queue_size:u32;
        let queue_bytes_num:u32;
        if bytes_num > (u32::MAX as u64) {

            // 如果 计算出的字节数超出最大范围, 强制按照 最大字节数量 / 最大包长度 来设置批次大小
            queue_size = u32::MAX / (pkt_len as u32);

            // 按照重新计算出的 批次大小, 重新计算 队列字节数量
            queue_bytes_num = queue_size * (pkt_len as u32);

            warn!("{}", SYS.get_info("warn","batch_size_reset"));
        } else {
            queue_size = batch_size as u32;
            queue_bytes_num = bytes_num as u32;
        }


        let pcap_sender = pcap::Capture::from_device(interface_name)
            .map_err(|_|{
                error!("{}", SYS.get_info("err","open_pcap_sender_failed"));
                exit(1)
            }).unwrap()
            .open()
            .map_err(|_|{
                error!("{}", SYS.get_info("err","open_pcap_sender_failed"));
                exit(1)
            }).unwrap();

        let send_queue = SendQueue::new(queue_bytes_num).map_err(
            |_|{
                error!("{}", SYS.get_info("err","create_send_queue_failed"));
                exit(1)
            }
        ).unwrap();


        (pcap_sender, send_queue, queue_size)

    }
}