use std::process::exit;
use std::sync::Arc;
use std::thread;
use std::thread::JoinHandle;
use ahash::AHashMap;
use bitvec::macros::internal::funty::Fundamental;
use chrono::Local;
use log::error;
use crate::{computing_time, creat_channels, ending_the_receiving_thread, init_var, prepare_data, recv_ready, SYS, wait_sender_threads, write_to_summary};
use crate::core::conf::tools::args_parse::target_iterator::TarIterBaseConf;
use crate::core::receiver::pcap::PcapReceiver;
use crate::core::sender::{pmap_full_scan_send_v6, pmap_recommend_new_scan_send_v6_port, pmap_recommend_scan_send_v6_port};
use crate::modes::ModeMethod;
use crate::modes::v6::pmap::PmapV6;
use crate::modules::output_modules::OutputMod;
use crate::modules::target_iterators::{PmapGraph, PmapState};
use crate::tools::check_duplicates::bit_map::{BitMapV6Pattern, BitMapV6PatternPort};
use crate::tools::check_duplicates::hash_set::{HashSetV6, HashSetV6Port};

enum Recorder6 {
    B6(JoinHandle<BitMapV6Pattern>),
    H6(JoinHandle<HashSetV6>)
}

enum Recorder6P {
    B6P(JoinHandle<BitMapV6PatternPort>),
    H6P(JoinHandle<HashSetV6Port>)
}

impl ModeMethod for PmapV6 {
    fn execute(&self) {

        // 定义 概率相关图
        let mut graph;
        // 初始化 输出模块
        let mut out_mod = OutputMod::init(&self.receiver_conf.output_v6);

        // 定义 开始的时间
        let start_time;
        // 初始化全局 发送线程消息  接收线程消息
        init_var!(u64; 0; total_send_success, total_send_failed, total_blocked);
        init_var!(usize; 0; total_ip_count, total_pair_count);

        // 如果 两者不等, 说明 不只有完全扫描; 如果 两者相等, 说明 只有完全扫描
        let recommend_scan = self.full_scan_last_index != self.tar_iter_without_port.p_sub_one;

        // 预扫描阶段
        {
            creat_channels!((recv_ready_sender, recv_ready_receiver, bool),(recv_close_time_sender, recv_close_time_receiver, i64));

            let full_scan_result = {
                // 完全扫描 接收线程  数据准备
                prepare_data!(self; clone; base_conf, receiver_conf, probe, tar_ports);
                let sports = self.sender_conf.source_ports.clone();
                // 执行接收线程
                if self.pmap_use_hash_recorder {
                    prepare_data!(self; as_usize; tar_ip_num);
                    Recorder6P::H6P(thread::spawn(move || {
                        let recorder = HashSetV6Port::new(tar_ip_num);
                        PcapReceiver::pmap_full_scan_v6(0, base_conf, receiver_conf, probe, sports, recorder,
                                                        recv_ready_sender, recv_close_time_receiver)
                    }))
                } else {
                    prepare_data!(self; ip_bits_num, base_ip_val, mask);
                    prepare_data!(self; clone; parts);
                    Recorder6P::B6P(thread::spawn(move || {
                        // 注意: 这里应该用 全部目标范围, 而不是只有预探测目标范围
                        let bit_map = BitMapV6PatternPort::new(ip_bits_num, base_ip_val, mask, parts, tar_ports);
                        PcapReceiver::pmap_full_scan_v6(0, base_conf, receiver_conf, probe, sports, bit_map,
                                                        recv_ready_sender, recv_close_time_receiver)
                    }))
                }
            };

            {   // 只有接收线程准备完毕后，发送线程才能继续执行
                recv_ready!(recv_ready_receiver);

                // 获取 完全扫描的多线程任务分配列表
                let full_scan_tar_ranges = TarIterBaseConf::cycle_group_assign_targets_u128(self.full_scan_last_index, self.sender_conf.send_thread_num as u128);

                // 记录 开始发送的时间
                start_time = Local::now();

                // 执行 完全扫描 发送线程
                let mut full_scan_sender_threads = vec![];
                for target_range in full_scan_tar_ranges.into_iter() {
                    // 发送线程 数据准备
                    prepare_data!(self; clone; blocker, base_conf, sender_conf, probe, tar_ports);
                    // 初始化 局部目标迭代器
                    let target_iter = self.tar_iter_without_port.init(target_range.0, target_range.1);

                    let full_scan_sender = thread::spawn(move || {
                        pmap_full_scan_send_v6(0, target_iter, blocker, probe, tar_ports, base_conf, sender_conf)
                    });

                    full_scan_sender_threads.push(full_scan_sender);
                }

                // 等待 发送线程 执行完毕
                wait_sender_threads!(full_scan_sender_threads; send_success, send_failed, blocked; {
                    total_send_success += send_success; total_send_failed += send_failed; total_blocked += blocked;
                });

                // 计算终止时间 并向接收线程传递
                ending_the_receiving_thread!(self; recv_close_time_sender);
            }

            // 完全扫描全局迭代器
            let full_scan_iter = self.tar_iter_without_port.init(1, self.full_scan_last_index);
            match full_scan_result {
                Recorder6P::B6P(b) => {
                    match &b.join() {
                        Ok(bit_map) => {
                            if recommend_scan {     // 将完全扫描阶段的结果进行输出, 使用结果对概率相关图进行训练
                                graph = Arc::new(PmapGraph::new(self.tar_ports.clone()));
                                match Arc::get_mut(&mut graph) {
                                    Some(g_ptr) => {
                                        let (ip_count, pair_count) = Self::full_scan_output_and_train(full_scan_iter, bit_map,  &self.blocker, &mut out_mod, g_ptr);
                                        total_ip_count += ip_count;
                                        total_pair_count += pair_count;
                                    }
                                    None => { error!("{}", SYS.get_info("err", "get_graph_arc_failed")); exit(1) }
                                }
                            } else {        // 将完全扫描阶段的结果进行输出
                                let (ip_count, pair_count) = Self::full_scan_output(full_scan_iter, bit_map,  &self.blocker, &mut out_mod);
                                total_ip_count += ip_count;
                                total_pair_count += pair_count;
                                graph = Arc::new(PmapGraph::new_void());
                            }
                        }
                        Err(_) => { error!("{}", SYS.get_info("err", "recv_thread_err")); exit(1) }
                    }
                }
                Recorder6P::H6P(h) => {
                    match &h.join() {
                        Ok(hash_set) => {
                            if recommend_scan {     // 将完全扫描阶段的结果进行输出, 使用结果对概率相关图进行训练
                                graph = Arc::new(PmapGraph::new(self.tar_ports.clone()));
                                match Arc::get_mut(&mut graph) {
                                    Some(g_ptr) => {
                                        let (ip_count, pair_count) = Self::full_scan_output_and_train(full_scan_iter, hash_set, &self.blocker, &mut out_mod, g_ptr);
                                        total_ip_count += ip_count;
                                        total_pair_count += pair_count;
                                    }
                                    None => { error!("{}", SYS.get_info("err", "get_graph_arc_failed")); exit(1) }
                                }
                            } else {        // 将完全扫描阶段的结果进行输出
                                let (ip_count, pair_count) = Self::full_scan_output(full_scan_iter, hash_set,  &self.blocker, &mut out_mod);
                                total_ip_count += ip_count;
                                total_pair_count += pair_count;
                                graph = Arc::new(PmapGraph::new_void());
                            }
                        }
                        Err(_) => { error!("{}", SYS.get_info("err", "recv_thread_err")); exit(1) }
                    }
                }
            }
        }

        // 活跃端口推荐探测阶段
        if recommend_scan {

            // 获取不同批次的索引段
            let batch_ranges = TarIterBaseConf::cycle_group_assign_targets_u128_part(
                self.full_scan_last_index, self.tar_iter_without_port.p_sub_one, self.pmap_batch_num as u128);

            for batch_range in batch_ranges.into_iter() {

                // 状态库 (批次)
                // 状态标签 -> 状态指针
                // 状态由 有序(从小到大)开放端口集合 生成, 如 开放端口集合为[3, 1, 2], 状态标签为 1,2,3
                let mut states_map:AHashMap<String, Arc<PmapState>> = AHashMap::new();

                // 生成 pmap迭代器 队列
                let mut pmap_iter_queue= Self::create_pmap6_iter_queue(
                    batch_range.0-1, batch_range.1, self.sender_conf.send_thread_num as u128, &self.tar_iter_without_port);

                let mut sent_port_count_add_one:u32 = 0;
                loop {
                    // 在一个循环内, 所有待探测地址被探测一个端口

                    // 如果  每个地址发送的端口数量加一  大于 预算时, 结束 推荐扫描
                    sent_port_count_add_one += 1; if sent_port_count_add_one > self.pmap_budget { break }

                    // 创建信息传递管道
                    creat_channels!((recv_ready_sender, recv_ready_receiver, bool),(recv_close_time_sender, recv_close_time_receiver, i64));

                    let recommend_scan_result = {
                        // 推荐扫描 接收线程 数据准备
                        prepare_data!(self; clone; base_conf, receiver_conf, probe);
                        let sports = self.sender_conf.source_ports.clone();
                        // 执行接收线程
                        if self.pmap_use_hash_recorder {
                            prepare_data!(self; as_usize; tar_ip_num);
                            Recorder6::H6(thread::spawn(move || {
                                let hash_set = HashSetV6::new(tar_ip_num);
                                PcapReceiver::pmap_recommend_scan_v6(0, base_conf, receiver_conf, probe, sports, hash_set,
                                                                     recv_ready_sender, recv_close_time_receiver)
                            }))
                        } else {
                            prepare_data!(self; ip_bits_num, base_ip_val, mask);
                            prepare_data!(self; clone; parts);
                            Recorder6::B6(thread::spawn(move || {
                                let bit_map = BitMapV6Pattern::new(ip_bits_num, base_ip_val, mask, parts);
                                PcapReceiver::pmap_recommend_scan_v6(0, base_conf, receiver_conf, probe, sports, bit_map,
                                                                     recv_ready_sender, recv_close_time_receiver)
                            }))
                        }
                    };

                    // 只有接收线程准备完毕后，发送线程才能继续执行
                    recv_ready!(recv_ready_receiver);

                    // 执行 推荐扫描 发送线程
                    let mut recommend_scan_sender_threads = vec![];
                    for pmap_iter in pmap_iter_queue.into_iter() {

                        prepare_data!(self; clone; blocker, base_conf, sender_conf, probe);
                        let graph_ptr = graph.clone();

                        let recommend_scan_sender = if sent_port_count_add_one == 1 {
                            thread::spawn(move || {
                                pmap_recommend_new_scan_send_v6_port(0, pmap_iter, blocker, probe, graph_ptr, base_conf, sender_conf)
                            })
                        } else {
                            thread::spawn(move || {
                                pmap_recommend_scan_send_v6_port(0, pmap_iter, blocker, probe, graph_ptr, base_conf, sender_conf)
                            })
                        };
                        recommend_scan_sender_threads.push(recommend_scan_sender);
                    }

                    // 等待 发送线程 执行完毕
                    pmap_iter_queue = vec![];
                    wait_sender_threads!(recommend_scan_sender_threads; send_success, send_failed, blocked, pmap_iter; {
                        pmap_iter_queue.push(pmap_iter);        // 接收迭代器队列

                        total_send_success += send_success;
                        total_send_failed += send_failed;
                        total_blocked += blocked;
                    });

                    // 计算终止时间 并向接收线程传递
                    ending_the_receiving_thread!(self; recv_close_time_sender);

                    // 使用这一轮次得到的数据对 ips_struct 和 状态库 进行更新
                    match Arc::get_mut(&mut graph) {
                        Some(g_ptr) => {
                            match recommend_scan_result {
                                Recorder6::B6(b) =>
                                    if let Ok(bit_map) = &b.join() {
                                        Self::pmap_receive(bit_map, g_ptr, &mut states_map, &mut pmap_iter_queue, &self.blocker);
                                    },
                                Recorder6::H6(h) =>
                                    if let Ok(hash_set) = &h.join() {
                                        Self::pmap_receive(hash_set, g_ptr, &mut states_map, &mut pmap_iter_queue, &self.blocker);
                                    },
                            }
                        }       // 如果 获取概率相关图的可变指针失败
                        None => { error!("{}", SYS.get_info("err", "get_graph_arc_failed")); exit(1) }
                    }
                }

                // 清理 状态库
                drop(states_map);

                // 输出 本推荐轮次结果, 更新概率相关图
                if self.pmap_allow_graph_iter {
                    match Arc::get_mut(&mut graph) {
                        Some(g_ptr) => {                 // 使用 开放端口列表 对 概率相关图 进行更新
                            let (ip_count, pair_count) = Self::recommend_scan_output_train(g_ptr, pmap_iter_queue, &mut out_mod, &self.blocker);
                            total_ip_count += ip_count;
                            total_pair_count += pair_count;
                        }
                        None => { error!("{}", SYS.get_info("err", "get_graph_arc_failed"));  exit(1) }
                    }
                } else {
                    let (ip_count, pair_count) = Self::recommend_scan_output(pmap_iter_queue, &mut out_mod, &self.blocker);
                    total_ip_count += ip_count;
                    total_pair_count += pair_count;
                }
            }
            // 清理 概率相关图
            drop(graph);
        }

        // 探测 和 接收 执行完毕
        println!("{} {} {} {}", SYS.get_info("print", "send_finished"), total_send_success, total_send_failed, total_blocked);
        println!("{} {} {}", SYS.get_info("print", "pmap_scan_finished"), total_ip_count, total_pair_count);
        computing_time!(start_time; end_time, running_time);

        write_to_summary!(self; "PmapV6"; "result";
            [start_time, end_time, running_time, total_send_success, total_send_failed, total_blocked, total_ip_count, total_pair_count;]
        );
    }
}