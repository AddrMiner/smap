use std::process::exit;
use std::sync::Arc;
use std::thread;
use ahash::AHashMap;
use chrono::Local;
use log::error;
use crate::{computing_time, creat_channels, ending_the_receiving_thread, init_var, prepare_data, recv_ready, wait_sender_threads, write_to_summary, SYS};
use crate::core::conf::tools::args_parse::ip::ipv6::get_ipv6_addrs_from_file;
use crate::core::receiver::pcap::PcapReceiver;
use crate::core::sender::{pmap_file_full_scan_send_v6, pmap_file_recommend_new_scan_send_v6_port, pmap_file_recommend_scan_send_v6_port};
use crate::modes::ModeMethod;
use crate::modes::v6::pmap_file::PmapFileV6;
use crate::modules::output_modules::OutputMod;
use crate::modules::target_iterators::{PmapGraph, PmapState};
use crate::tools::check_duplicates::hash_set::HashSetV6Port;
use crate::tools::others::split::split_chains;

impl ModeMethod for PmapFileV6 {
    fn execute(&self) {

        // 从 文件 中读取所有目标地址
        // 注意: 该地址列表经过完全随机化
        let mut tar_ips = get_ipv6_addrs_from_file(&self.path, None);
        if tar_ips.is_empty() { error!("{}", SYS.get_info("err", "target_ips_not_exist")); exit(1) }

        // 取出 总目标数量
        let tar_ip_num = tar_ips.len();
        // 取出 总探测端口数量
        let tar_ports_num = self.tar_ports.len();
        
        // 计算 预扫描抽样数量
        let sample_num = Self::get_sample_num(tar_ip_num, self.sampling_pro, self.min_sample_num);

        // 定义 概率相关图
        let mut graph;
        // 初始化 输出模块
        let mut out_mod = OutputMod::init(&self.receiver_conf.output_v6);

        // 定义 开始的时间
        let start_time;
        // 初始化全局 发送线程消息  接收线程消息
        init_var!(u64; 0; total_send_success, total_send_failed);
        init_var!(usize; 0; total_ip_count, total_pair_count);

        // 如果 抽样数量 小于 总数量, 说明 不只有完全扫描;
        let recommend_scan = sample_num < tar_ip_num;
        
        // 预扫描阶段
        {
            // 取出 预扫描 的探测目标
            let pre_scan_targets:Vec<u128> = tar_ips.drain(..sample_num).collect();
            
            creat_channels!((recv_ready_sender, recv_ready_receiver, bool),(recv_close_time_sender, recv_close_time_receiver, i64));

            let full_scan_result = {
                // 完全扫描 接收线程  数据准备
                prepare_data!(self; clone; base_conf, receiver_conf, probe);
                let sports = self.sender_conf.source_ports.clone();

                thread::spawn(move || {
                    let recorder = HashSetV6Port::new(sample_num * tar_ports_num);
                    PcapReceiver::pmap_full_scan_v6(0, base_conf, receiver_conf, probe, sports, recorder,
                                                    recv_ready_sender, recv_close_time_receiver)
                })
            };

            {
                // 只有接收线程准备完毕后，发送线程才能继续执行
                recv_ready!(recv_ready_receiver);

                // 记录 开始发送的时间
                start_time = Local::now();

                // 将 预探测的探测目标 切割后分给各个发送线程
                let targets_list = split_chains(pre_scan_targets.clone(), self.sender_conf.send_thread_num);

                // 执行 完全扫描 发送线程
                let mut full_scan_sender_threads = vec![];
                for cur_target in targets_list.into_iter() {
                    prepare_data!(self; clone; base_conf, sender_conf, probe, tar_ports);
                    let full_scan_sender = thread::spawn(move || {
                        pmap_file_full_scan_send_v6(0, probe, cur_target, tar_ports, base_conf, sender_conf)
                    });
                    full_scan_sender_threads.push(full_scan_sender);
                }

                // 等待 发送线程 执行完毕
                wait_sender_threads!(full_scan_sender_threads; send_success, send_failed; {
                    total_send_success += send_success; total_send_failed += send_failed;
                });

                // 计算终止时间 并向接收线程传递
                ending_the_receiving_thread!(self; recv_close_time_sender);
            }
            
            match full_scan_result.join() {
                Ok(hash_set) => {
                    if recommend_scan {
                        // 将完全扫描阶段的结果进行输出, 使用结果对概率相关图进行训练
                        graph = Arc::new(PmapGraph::new(self.tar_ports.clone(), self.port_num_limit));
                        match Arc::get_mut(&mut graph) {
                            Some(g_ptr) => {
                                let (ip_count, pair_count) = Self::full_scan_output_and_train(pre_scan_targets, hash_set, &mut out_mod, g_ptr);
                                total_ip_count += ip_count;
                                total_pair_count += pair_count;
                            }
                            None => { error!("{}", SYS.get_info("err", "get_graph_arc_failed")); exit(1) }
                        }
                    } else {
                        let (ip_count, pair_count) = Self::full_scan_output(pre_scan_targets, hash_set, &mut out_mod);
                        total_ip_count += ip_count;
                        total_pair_count += pair_count;
                        graph = Arc::new(PmapGraph::new_void());
                    }
                }
                Err(_) => { error!("{}", SYS.get_info("err", "recv_thread_err")); exit(1) }
            }
        }


        // 活跃端口推荐探测阶段
        if recommend_scan {

            // 将 推荐探测阶段的探测目标 切割后分给各个不同阶段
            let targets_list = split_chains(tar_ips, self.pmap_batch_num as usize);
            
            for cur_ips in targets_list {
                if cur_ips.is_empty() { continue }

                // 状态库 (批次)
                // 状态标签 -> 状态指针
                // 状态由 有序(从小到大)开放端口集合 生成, 如 开放端口集合为[3, 1, 2], 状态标签为 1,2,3
                let mut states_map: AHashMap<Vec<u16>, Arc<PmapState>> = AHashMap::new();

                // 计算当前目标数量
                let cur_ips_num = cur_ips.len();

                // 生成 pmap迭代器 队列
                let mut pmap_iter_queue = Self::create_pmap6_iter_queue(cur_ips, self.sender_conf.send_thread_num);

                let mut sent_port_count_add_one: u32 = 0;
                loop {
                    // 在一个循环内, 所有待探测地址被探测一个端口

                    // 如果  每个地址发送的端口数量加一  大于 预算时, 结束 推荐扫描
                    sent_port_count_add_one += 1;
                    if sent_port_count_add_one > self.pmap_budget { break }

                    // 创建信息传递管道
                    creat_channels!((recv_ready_sender, recv_ready_receiver, bool),(recv_close_time_sender, recv_close_time_receiver, i64));

                    let recommend_scan_result = {
                        // 推荐扫描 接收线程 数据准备
                        prepare_data!(self; clone; base_conf, receiver_conf, probe);
                        let sports = self.sender_conf.source_ports.clone();
                        thread::spawn(move || {
                            let hash_set = HashSetV6Port::new(cur_ips_num);
                            PcapReceiver::pmap_full_scan_v6(0, base_conf, receiver_conf, probe, sports, hash_set,
                                                                 recv_ready_sender, recv_close_time_receiver)
                        })
                    };

                    // 只有接收线程准备完毕后，发送线程才能继续执行
                    recv_ready!(recv_ready_receiver);

                    // 执行 推荐扫描 发送线程
                    let mut recommend_scan_sender_threads = vec![];
                    for pmap_iter in pmap_iter_queue.into_iter() {
                        prepare_data!(self; clone; base_conf, sender_conf, probe);
                        let graph_ptr = graph.clone();

                        let recommend_scan_sender = if sent_port_count_add_one == 1 {
                            thread::spawn(move || {
                                pmap_file_recommend_new_scan_send_v6_port(0, pmap_iter, probe, graph_ptr, base_conf, sender_conf)
                            })
                        } else {
                            thread::spawn(move || {
                                pmap_file_recommend_scan_send_v6_port(0, pmap_iter, probe, graph_ptr, base_conf, sender_conf)
                            })
                        };
                        recommend_scan_sender_threads.push(recommend_scan_sender);
                    }

                    // 等待 发送线程 执行完毕
                    pmap_iter_queue = vec![];
                    wait_sender_threads!(recommend_scan_sender_threads; send_success, send_failed, pmap_iter; {
                        pmap_iter_queue.push(pmap_iter);        // 接收迭代器队列

                        total_send_success += send_success;
                        total_send_failed += send_failed;
                    });

                    // 计算终止时间 并向接收线程传递
                    ending_the_receiving_thread!(self; recv_close_time_sender);

                    // 使用这一轮次得到的数据对 ips_struct 和 状态库 进行更新
                    match Arc::get_mut(&mut graph) {
                        Some(g_ptr) => {
                            if let Ok(hash_set) = recommend_scan_result.join() {
                                Self::pmap_receive(hash_set, g_ptr, &mut states_map, &mut pmap_iter_queue);
                            }
                        }
                        // 如果 获取概率相关图的可变指针失败
                        None => {
                            error!("{}", SYS.get_info("err", "get_graph_arc_failed"));
                            exit(1)
                        }
                    }
                }

                // 清理 状态库
                drop(states_map);

                // 输出 本推荐轮次结果, 更新概率相关图
                if self.pmap_allow_graph_iter {
                    match Arc::get_mut(&mut graph) {
                        Some(g_ptr) => {                 // 使用 开放端口列表 对 概率相关图 进行更新
                            let (ip_count, pair_count) = Self::recommend_scan_output_train(g_ptr, pmap_iter_queue, &mut out_mod);
                            total_ip_count += ip_count;
                            total_pair_count += pair_count;
                        }
                        None => {
                            error!("{}", SYS.get_info("err", "get_graph_arc_failed"));
                            exit(1)
                        }
                    }
                } else {
                    let (ip_count, pair_count) = Self::recommend_scan_output(pmap_iter_queue, &mut out_mod);
                    total_ip_count += ip_count;
                    total_pair_count += pair_count;
                }
            }

            // 清理 概率相关图
            drop(graph);
        }

        // 探测 和 接收 执行完毕
        println!("{} {} {} {}", SYS.get_info("print", "send_finished"), total_send_success, total_send_failed, 0);
        println!("{} {} {}", SYS.get_info("print", "pmap_scan_finished"), total_ip_count, total_pair_count);
        computing_time!(start_time; end_time, running_time);

        write_to_summary!(self; "PmapFileV6"; "result";
            [start_time, end_time, running_time, total_send_success, total_send_failed, total_ip_count, total_pair_count;]
        );
        
    }
}