use std::process::exit;
use log::error;
use pcap::{Capture, Linktype};
use crate::core::receiver::pcap::PcapReceiver;
use crate::SYS;

impl PcapReceiver {

    pub fn init(interface_name:&str, probe_mod_snap_len:usize, filter:&Option<String>) -> Self {


        let device = pcap::Device::from(interface_name);                    // 获得指定设备
        let capture = Capture::from_device(device);     // 由设备获得捕获

        let mut active_capture;
        if let Ok(inactive_capture) = capture {

            // 如果从指定网络接口获得 捕获
            let opened_capture = inactive_capture

                .buffer_size(SYS.get_conf("conf", "pcap_recv_buffer_size"))

                // 设置每个捕获的数据包的长度
                .snaplen(probe_mod_snap_len as i32)

                // 使网络接口能够捕获所有通过它的数据包，而不仅仅是那些目标为它的数据包
                .promisc(true)

                // 设置捕获的读取超时
                .timeout(SYS.get_conf("conf", "capture_timeout"))

                // 在即时模式下，数据包始终在到达后立即传送，没有缓冲
                .immediate_mode(true)

                // 打开捕获器
                .open();

            if let Ok(c) = opened_capture {
                // 如果成功开启

                // 设置非阻塞模式
                active_capture = c.setnonblock()
                    .map_err(|_|{
                        error!("{}", SYS.get_info("err", "receiver_set_nonblock"));
                        exit(1)
                    }).unwrap();
            } else {
                error!("{}", SYS.get_info("err", "open_capture_failed"));
                exit(1)
            }
        } else {
            error!("{}", SYS.get_info("err", "open_capture_failed"));
            exit(1)
        }


        let data_link_len:usize;
        {
            // 获取数据链路层类型，并进行相关处理
            match active_capture.get_datalink() {
                Linktype::ETHERNET => {
                    // 如果是 以太网
                    // 数据链路层的字节数， 用于分割掉数据链路层的包
                    data_link_len = 14;
                }

                Linktype::RAW => {
                    // 如果是 原始类型
                    // 数据链路层字节数设为0
                    data_link_len = 0;
                }

                _ => {
                    error!("{} {:?}", SYS.get_info("err", "data_link_type_not_supported"),
                        active_capture.get_datalink());

                    exit(1)
                }
            }
        }

        if let Some(program) = filter {
            // 如果设置了过滤器
            if let Err(_) = active_capture.filter(&program, true) {

                // 如果过滤器设置失败
                error!("{} {}",SYS.get_info("err", "set_filter_failed"), program);
                exit(1)
            }

        }

        Self {
            active_capture,
            data_link_len,
        }


    }
}