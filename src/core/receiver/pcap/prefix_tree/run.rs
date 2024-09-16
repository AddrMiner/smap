use std::process::exit;
use std::sync::Arc;
use std::sync::mpsc::{Receiver, Sender};
use ahash::AHashSet;
use chrono::Utc;
use log::error;
use crate::core::conf::set_conf::base_conf::BaseConf;
use crate::core::conf::set_conf::receiver_conf::ReceiverBaseConf;
use crate::core::receiver::pcap::{Codec, PcapReceiver};
use crate::modules::output_modules::OutputMethod;
use crate::modules::probe_modules::topology_probe::topo_mod_v6::TopoModV6;
use crate::modules::target_iterators::Ipv6VecDoubleTree;
use crate::SYS;

impl PcapReceiver {
    
    pub fn prefix_tree_scan_v6(
        interface_index:usize, mut output:Box<dyn OutputMethod>, 
        mut double_tree_struct:Ipv6VecDoubleTree, mut all_nodes:AHashSet<u128>,
        base_conf:Arc<BaseConf>, receiver_conf:Arc<ReceiverBaseConf>,
        probe_mod:Arc<TopoModV6>, sports:Vec<u16>,
        recv_ready_sender:Sender<bool>, recv_close_time_receiver:Receiver<i64>
    ) -> (Ipv6VecDoubleTree, AHashSet<u128>, Box<dyn OutputMethod>, Vec<(u128, u8, u8)>) {

        // 初始化 数据包捕获器
        let receiver = PcapReceiver::init(
            &base_conf.interface[interface_index].name_index.0,
            probe_mod.snap_len_v6, &receiver_conf.filter);
        
        // 初始化 拓扑探测模块
        let probe = TopoModV6::init(probe_mod, sports);

        // 复制加密机
        let aes_rand = base_conf.aes_rand.clone();

        // 初始化探测时间
        let mut tar_time = i64::MAX;          // 默认目标时间无穷大
        let mut act_count:u32 = 0;                 // 初始化活跃数据包计数
        let mut send_running = true;               // 发送进程 正在运行标识
        let act_check_count:u32 = SYS.get_conf("conf", "active_check_count");

        // 向主线程发送 接收线程 准备完毕的 管道消息
        if let Err(_) = recv_ready_sender.send(true) {
            error!("{}", SYS.get_info("err","recv_ready_send_failed"));
            exit(1)
        }

        drop(base_conf);
        drop(receiver_conf);

        for packet in receiver.active_capture.iter(Codec) {

            match packet {

                Ok(packet) => {

                    // 头部信息, 包含时间戳, 数据包长度等信息
                    let header = packet.header;
                    // 网络层数据包
                    let net_layer_data = &packet.data[receiver.data_link_len..];

                    let ip_ver = net_layer_data[0] >> 4;
                    if ip_ver == 6 {
                        // 如果是ipv6的数据包
                        PcapReceiver::prefix_scan_handle_packet_v6(&header.ts, &net_layer_data, &mut double_tree_struct,
                        &aes_rand, &probe, &mut all_nodes, &mut output);
                    }
                    // 如果是 ipv4 的包, 或者其它特殊类型, 不进行处理

                    {   // 计算终止条件
                        act_count += 1;
                        if act_count % act_check_count == 0 {
                            // 多少个数据包检查一次
                            if send_running {
                                // 还未收到 发送进程传递的 结束消息
                                match recv_close_time_receiver.try_recv() { // 检查有没有消息
                                    Ok(close_time) => {

                                        if  (header.ts.tv_sec as i64) >=  close_time {     // 检查有没有 达到 目标时间
                                            break                          // 如果达到就退出
                                        }

                                        tar_time = close_time;      // 将 从主线程传递过来的 关闭时间 赋值 给 目标时间

                                        send_running = false;       // 将 发送线程状态 设置为 关闭
                                    }
                                    Err(_) => {}     // 没消息，继续等
                                }
                            } else {
                                if  (header.ts.tv_sec as i64) >=  tar_time {     // 检查有没有 达到 目标时间
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
                                    break                          // 如果达到就退出
                                }

                                tar_time = close_time;      // 将 从主线程传递过来的 关闭时间 赋值 给 目标时间

                                send_running = false;       // 将 发送线程状态 设置为 关闭
                            }
                            Err(_) => {}     // 没消息，继续等
                        }

                    } else {        // 之前收到过消息

                        // 计算当前时间戳
                        let now_time = Utc::now().timestamp();
                        if  now_time >=  tar_time {     // 检查有没有 达到 目标时间
                            break                          // 如果达到就退出
                        }

                    }
                }
            }
        }

        // 打印本轮次沉默目标, 并生成下一轮次的探测目标
        let new_targets = double_tree_struct.gen_scan_targets_and_print_silent(&probe, &mut output);

        // 关闭输出
        output.close_output();
        
        (double_tree_struct, all_nodes, output, new_targets)
    }
}