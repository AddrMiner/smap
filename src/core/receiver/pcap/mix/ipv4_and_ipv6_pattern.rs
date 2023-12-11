use std::process::exit;
use std::sync::Arc;
use std::sync::mpsc::{Receiver, Sender};
use chrono::Utc;
use log::error;
use crate::core::conf::set_conf::base_conf::BaseConf;
use crate::core::conf::set_conf::receiver_conf::ReceiverBaseConf;
use crate::core::receiver::pcap::{Codec, PcapReceiver};
use crate::core::receiver::{ReceiverInfoV6, ReceiverInfoV4};
use crate::modules::output_modules::OutputMod;
use crate::modules::probe_modules::probe_mod_v4::ProbeModV4;
use crate::modules::probe_modules::probe_mod_v6::ProbeModV6;
use crate::SYS;
use crate::tools::check_duplicates::bit_map_v4_port::BitMapV4Port;
use crate::tools::check_duplicates::bit_map_v6_pattern_port::BitMapV6PatternPort;

impl PcapReceiver {

    #[allow(dead_code)]
    pub fn run_v4_v6_pattern(// 网络接口下标, 用来指定接收器绑定的网络接口
                     interface_index:usize,
                     base_conf:Arc<BaseConf>, receiver_conf:Arc<ReceiverBaseConf>,
                     // 探测模块用来验证信息, 处理数据包
                     probe_mod_v4:Arc<ProbeModV4>, probe_mod_v6:Arc<ProbeModV6>,
                     // 起始地址 和 目标地址数量, 用来初始化位图
                     start_ip_v4:u32, end_ip_v4:u32, tar_ip_num_v4:u64, sports:Vec<u16>, tar_ports:Vec<u16>,
                     // 二进制位数量, 基础ip值, 掩码, 片段信息, 用来初始化位图
                     bits_num:u32, base_ip_val:u128, mask:u128, parts:Vec<(u32, u32)>,
                     // 接收准备完成管道: 用于在接收线程准备好进行接收时,向主线程发送允许执行发送线程的信号
                     // 接收关闭时间管道: 用于接收从主线程传递过来的接收线程关闭时间
                     recv_ready_sender:Sender<bool>, recv_close_time_receiver:Receiver<i64>) -> (ReceiverInfoV4, ReceiverInfoV6) {


        // 将 两种模块 捕获数据包的最大长度中的最大值 作为 捕获数据包的最大长度
        let snap_len = if probe_mod_v4.snap_len_v4 > probe_mod_v6.snap_len_v6 {
            probe_mod_v4.snap_len_v4
        } else {
            probe_mod_v6.snap_len_v6
        };

        // 初始化 探测模块
        let probe_v4 = ProbeModV4::init(probe_mod_v4, sports.clone());
        let probe_v6 = ProbeModV6::init(probe_mod_v6, sports);

        // 初始化 输出模块
        let mut output_v4 = OutputMod::init(&receiver_conf.output_v4);
        let mut output_v6 = OutputMod::init(&receiver_conf.output_v6);

        // 向输出文件输入首行
        output_v4.writer_line(&probe_v4.print_header());
        output_v6.writer_line(&probe_v6.print_header());

        // 初始化 数据包捕获器
        let receiver = PcapReceiver::init(
            &base_conf.interface[interface_index].name_index.0,
            snap_len, &receiver_conf.filter);

        // 接收线程信息统计
        let mut receiver_info_v4 = ReceiverInfoV4::new();
        let mut receiver_info_v6 = ReceiverInfoV6::new();

        // 初始化 位图查重器
        let mut bit_map_v4 = BitMapV4Port::new(start_ip_v4, end_ip_v4,tar_ip_num_v4, tar_ports.clone());
        let mut bit_map_v6 = BitMapV6PatternPort::new(bits_num, base_ip_val, mask, parts, tar_ports);

        let aes_rand = base_conf.aes_rand.clone();

        // 初始化探测时间
        let mut tar_time = i64::MAX;          // 默认目标时间无穷大
        let mut act_count:u32 = 0;                 // 初始化活跃数据包计数
        let mut send_running = true;               // 发送进程 正在运行标识
        let act_check_count:u32 = SYS.get_conf("conf", "active_check_count");

        // 向主线程发送 接收线程 准备完毕的 管道消息
        if let Err(_) = recv_ready_sender.send(true) {
            error!("{}", SYS.get_info("err","recv_ready_send_failed"));
            exit(1);
        }

        drop(base_conf);
        drop(receiver_conf);

        let data_link_len = receiver.data_link_len as u32;
        for packet in receiver.active_capture.iter(Codec) {

            match packet {

                Ok(packet) => {

                    // 头部信息, 包含时间戳, 数据包长度等信息
                    let header = packet.header;
                    // 数据链路层报头
                    let data_link_header = &packet.data[..receiver.data_link_len];
                    // 网络层数据包
                    let net_layer_data = &packet.data[receiver.data_link_len..];

                    let ip_ver = net_layer_data[0] >> 4;
                    if ip_ver == 4 {
                        Self::handle_packet_v4(&header,data_link_header,data_link_len,
                                               net_layer_data, &aes_rand, &mut bit_map_v4,
                                               &mut receiver_info_v4, &probe_v4, &mut output_v4);
                    }
                    if ip_ver == 6 {
                        // 如果是ipv6的数据包
                        Self::handle_packet_v6_pattern(&header,data_link_header,data_link_len,
                                               net_layer_data, &aes_rand, &mut bit_map_v6,
                                               &mut receiver_info_v6, &probe_v6, &mut output_v6);
                    }
                    // 如果是 其它特殊类型, 不进行处理

                    {   // 计算终止条件
                        act_count += 1;
                        if act_count % act_check_count == 0 {
                            // 多少个数据包检查一次
                            if send_running {
                                // 还未收到 发送进程传递的 结束消息
                                match recv_close_time_receiver.try_recv() { // 检查有没有消息
                                    Ok(close_time) => {

                                        if  (header.ts.tv_sec as i64) >=  close_time {     // 检查有没有 达到 目标时间
                                            output_v4.close_output();
                                            output_v6.close_output();
                                            break                          // 如果达到就退出
                                        }

                                        tar_time = close_time;      // 将 从主线程传递过来的 关闭时间 赋值 给 目标时间

                                        send_running = false;       // 将 发送线程状态 设置为 关闭
                                    }
                                    Err(_) => {     // 没消息，继续等
                                    }
                                }
                            } else {
                                if  (header.ts.tv_sec as i64) >=  tar_time {     // 检查有没有 达到 目标时间
                                    output_v4.close_output();
                                    output_v6.close_output();
                                    break                        // 如果达到就退出
                                }
                            }
                            act_count = 0;      // 重新 设为 0
                        }
                    }
                },

                Err(_) => {         // 主要是超时错误， 没接收到数据包就 报错

                    if send_running {   // 还未收到 发送进程传递的 结束消息

                        match recv_close_time_receiver.try_recv() { // 检查有没有消息
                            Ok(close_time) => {

                                let now_time = Utc::now().timestamp();
                                if  now_time >=  close_time {     // 检查有没有 达到 目标时间
                                    output_v4.close_output();
                                    output_v6.close_output();
                                    break                          // 如果达到就退出
                                }

                                tar_time = close_time;      // 将 从主线程传递过来的 关闭时间 赋值 给 目标时间

                                send_running = false;       // 将 发送线程状态 设置为 关闭
                            }
                            Err(_) => {     // 没消息，继续等
                            }
                        }

                    } else {        // 之前收到过消息

                        // 计算当前时间戳
                        let now_time = Utc::now().timestamp();
                        if  now_time >=  tar_time {     // 检查有没有 达到 目标时间
                            output_v4.close_output();
                            output_v6.close_output();
                            break                          // 如果达到就退出
                        }

                    }
                }
            }
        }

        (receiver_info_v4, receiver_info_v6)

    }
}