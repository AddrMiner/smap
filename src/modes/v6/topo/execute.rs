

use std::process::exit;
use std::thread;
use chrono::Local;
use log::error;
use crate::core::receiver::pcap::PcapReceiver;
use crate::{computing_time, creat_channels, ending_the_receiving_thread, init_var, prepare_data, recv_ready, SYS, wait_sender_threads, write_to_summary};
use crate::core::conf::tools::args_parse::target_iterator::TarIterBaseConf;
use crate::core::sender::{topo_pre_scan_send_v6, topo_scan_send_v6};
use crate::modes::ModeMethod;
use crate::modes::v6::topo::Topo6;
use crate::modules::output_modules::OutputMod;
use crate::modules::target_iterators::{TopoIterV6, TopoStateChainV6};
use crate::tools::others::split::split_chains;

impl ModeMethod for Topo6 {
    fn execute(&self) {

        // 定义 状态链
        let mut state_chain;
        // 定义 开始的时间
        let start_time;
        // 初始化全局 发送线程消息
        init_var!(u64; 0; total_send_success, total_send_failed, total_blocked);
        // 初始化 输出模块
        let mut out_mod = OutputMod::init(&self.receiver_conf.output_v6);

        // 预扫描阶段
        // 对 所有目标地址 进行探测, 取得 所有存活目标 的 跳数 和 延迟
        {
            // 首次预扫描
            {
                creat_channels!((recv_ready_sender, recv_ready_receiver, bool),(recv_close_time_sender, recv_close_time_receiver, i64));

                // 执行接收线程
                let receiver_res;
                {
                    prepare_data!(self; ip_bits_num, base_ip_val, mask);
                    prepare_data!(self; clone; parts, base_conf, receiver_conf, probe);
                    let sports = self.sender_conf.source_ports.clone();
                    let ip_move_len = self.tar_iter.ip_move_len.clone();

                    receiver_res = thread::spawn(move || {
                        // ip状态链  用于记录每个ip的状态   ( 是否接收到的标志(1比特) | 最大ttl-1 (6比特) ), 并用于响应查重
                        let state_chain: TopoStateChainV6 = TopoStateChainV6::new(ip_bits_num, base_ip_val,
                                                                                  mask, parts, ip_move_len);

                        PcapReceiver::topo_pre_scan_v6(0, out_mod, base_conf, receiver_conf,
                                                       probe, sports, state_chain,
                                                       recv_ready_sender, recv_close_time_receiver)
                    });
                }
                {   // 只有接收线程准备完毕后，发送线程才能继续执行
                    recv_ready!(recv_ready_receiver);

                    // 获取 预扫描的多线程任务分配列表
                    let tar_ranges = TarIterBaseConf::cycle_group_assign_targets_u128(
                        self.tar_iter.p_sub_one, self.sender_conf.send_thread_num as u128);

                    // 记录 开始发送的时间
                    start_time = Local::now();

                    // 执行 预扫描 发送线程
                    let mut pre_scan_sender_threads = vec![];
                    for tar_range in tar_ranges.into_iter() {
                        // 发送线程 数据准备
                        let max_ttl = self.max_ttl;
                        prepare_data!(self; clone; blocker, base_conf, sender_conf, probe);
                        // 初始化 局部目标迭代器
                        let tar_iter = self.tar_iter.init(tar_range.0, tar_range.1);

                        pre_scan_sender_threads.push(thread::spawn(move || {
                            topo_pre_scan_send_v6(0, tar_iter, blocker, max_ttl, probe, base_conf, sender_conf)
                        }));
                    }

                    // 等待 发送线程 执行完毕
                    wait_sender_threads!(pre_scan_sender_threads; send_success, send_failed, blocked; {
                        total_send_success += send_success; total_send_failed += send_failed; total_blocked += blocked;
                    });

                    // 计算终止时间 并向接收线程传递
                    ending_the_receiving_thread!(self; recv_close_time_sender);
                }

                // 等待接收线程按照预定时间关闭
                if let Ok((s_chain, output)) = receiver_res.join() {
                    state_chain = s_chain; out_mod = output;
                } else { error!("{}", SYS.get_info("err", "recv_thread_err"));exit(1) }
            }

            // 第二次预扫描  使用 用于补足预扫描结果
            if let Some(sub_probe_mod) = &self.sub_probe {
                // 为 发送线程 准备的 状态链
                let state_chain_for_sender = state_chain.state_chain.clone();

                creat_channels!((recv_ready_sender, recv_ready_receiver, bool),(recv_close_time_sender, recv_close_time_receiver, i64));
                // 执行接收线程
                let receiver_res;
                {
                    let sub_probe = sub_probe_mod.clone();
                    prepare_data!(self; clone; base_conf, receiver_conf);
                    let sports = self.sender_conf.source_ports.clone();

                    receiver_res = thread::spawn(move || {
                        PcapReceiver::topo_sub_pre_scan_v6(0, out_mod, base_conf, receiver_conf,
                                                           sub_probe, sports, state_chain,
                                                           recv_ready_sender, recv_close_time_receiver)
                    });
                }
                {   // 只有接收线程准备完毕后，发送线程才能继续执行
                    recv_ready!(recv_ready_receiver);

                    // 执行 辅助预扫描 发送线程
                    let mut sub_pre_scan_sender_threads = vec![];
                    let mut cur_start_index = 0;
                    let split_chains = split_chains(state_chain_for_sender, self.sender_conf.send_thread_num);
                    for split_chain in split_chains.into_iter() {
                        // 发送线程 数据准备
                        let max_ttl = self.max_ttl;
                        let sub_probe = sub_probe_mod.clone();
                        prepare_data!(self; clone; blocker, base_conf, sender_conf);

                        // 初始化 局部目标迭代器
                        let cur_chain_len = split_chain.len();
                        let tar_iter = TopoIterV6::new(cur_start_index, split_chain, self.base_ip_val,
                                                       self.tar_iter.ip_move_len.clone(), &mut self.base_conf.aes_rand.rng.clone());
                        cur_start_index += cur_chain_len;

                        sub_pre_scan_sender_threads.push(thread::spawn(move || {
                            topo_pre_scan_send_v6(0, tar_iter, blocker, max_ttl, sub_probe, base_conf, sender_conf)
                        }));
                    }

                    // 等待 发送线程 执行完毕
                    wait_sender_threads!(sub_pre_scan_sender_threads; send_success, send_failed, blocked; {
                        total_send_success += send_success; total_send_failed += send_failed; total_blocked += blocked;
                    });

                    // 计算终止时间 并向接收线程传递
                    ending_the_receiving_thread!(self; recv_close_time_sender);
                }
                // 等待接收线程按照预定时间关闭
                if let Ok((s_chain, output)) = receiver_res.join() {
                    state_chain = s_chain; out_mod = output;
                } else { error!("{}", SYS.get_info("err", "recv_thread_err")); exit(1) }
            }
        }

        // 全局拓扑扫描
        {
            while state_chain.target_count > 0 {
                // 只要 目标数量 大于0, 就不断地进行循环扫描

                creat_channels!((recv_ready_sender, recv_ready_receiver, bool),(recv_close_time_sender, recv_close_time_receiver, i64));

                // 为 发送线程 准备的 状态链
                let state_chain_for_sender = state_chain.state_chain.clone();

                // 执行接收线程
                let receiver_res;
                {
                    prepare_data!(self; clone; base_conf, receiver_conf, probe);
                    let sports = self.sender_conf.source_ports.clone();

                    receiver_res = thread::spawn(move || {
                        PcapReceiver::topo_scan_v6(0, out_mod, base_conf, receiver_conf,
                                                   probe, sports, state_chain,
                                                   recv_ready_sender, recv_close_time_receiver)
                    });
                }
                {
                    // 只有接收线程准备完毕后，发送线程才能继续执行
                    recv_ready!(recv_ready_receiver);

                    // 执行 拓扑扫描 发送线程
                    let mut topo_scan_sender_threads = vec![];
                    let mut cur_start_index = 0;
                    let split_chains = split_chains(state_chain_for_sender, self.sender_conf.send_thread_num);
                    for split_chain in split_chains.into_iter() {
                        // 发送线程 数据准备

                        prepare_data!(self; clone; base_conf, sender_conf, probe);
                        // 初始化 局部目标迭代器
                        let cur_chain_len = split_chain.len();
                        let tar_iter = TopoIterV6::new(cur_start_index, split_chain, self.base_ip_val,
                                                       self.tar_iter.ip_move_len.clone(), &mut self.base_conf.aes_rand.rng.clone());
                        cur_start_index += cur_chain_len;

                        topo_scan_sender_threads.push(thread::spawn(move || {
                            topo_scan_send_v6(0, tar_iter, probe, base_conf, sender_conf)
                        }));
                    }

                    // 等待 发送线程 执行完毕
                    wait_sender_threads!(topo_scan_sender_threads; send_success, send_failed; {
                        total_send_success += send_success; total_send_failed += send_failed;
                    });
                    // 计算终止时间 并向接收线程传递
                    ending_the_receiving_thread!(self; recv_close_time_sender);
                }
                // 等待接收线程按照预定时间关闭
                if let Ok((s_chain, output)) = receiver_res.join() {
                    // 处理接收线程返回的信息
                    state_chain = s_chain;
                    out_mod = output;
                } else { error!("{}", SYS.get_info("err", "recv_thread_err")); exit(1) }
            }
        }

        // 探测 和 接收 执行完毕
        println!("{} {} {} {}", SYS.get_info("print", "send_finished"), total_send_success, total_send_failed, total_blocked);

        computing_time!(start_time; end_time, running_time);
        write_to_summary!(self; "TopoV6"; "result";
            [start_time, end_time, running_time, total_send_success, total_send_failed, total_blocked;]
        );
    }
}