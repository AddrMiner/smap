use std::net::Ipv4Addr;
use std::process::exit;
use std::sync::{Arc};
use std::thread;
use ahash::AHashMap;
use chrono::Local;
use log::{error};
use crate::core::conf::tools::args_parse::target_iterator::TarIterBaseConf;
use crate::core::receiver::pcap::PcapReceiver;
use crate::core::sender::{pmap_full_scan_send_v4, pmap_recommend_scan_send_v4_port};
use crate::modes::ModeMethod;
use crate::modes::v4::pmap::PmapV4;
use crate::modes::v4::pmap::tools::{full_scan_output_v4, full_scan_output_and_train_v4, create_pmap4_iter_queue, pmap_receive};
use crate::modules::output_modules::{OutputMod};
use crate::modules::target_iterators::{PmapGraph, PmapState};
use crate::{computing_time, creat_channels, ending_the_receiving_thread, init_var, prepare_data, recv_ready, SYS, wait_sender_threads, write_to_summary};
use crate::tools::check_duplicates::bit_map_v4::BitMapV4;
use crate::tools::check_duplicates::bit_map_v4_port::BitMapV4Port;

impl ModeMethod for PmapV4 {
    fn execute(&self) {

        // 定义 概率相关图
        let mut graph;

        // 初始化 输出模块
        let mut out_mod = OutputMod::init(&self.receiver_conf.output_v4);

        // 初始化全局 发送线程消息
        init_var!(u64; 0; total_send_success, total_send_failed, total_blocked);
        // 初始化全局 接收线程消息
        init_var!(usize; 0; total_ip_count, total_pair_count);

        // 如果 两者不等, 说明 不只有完全扫描; 如果 两者相等, 说明 只有完全扫描
        let recommend_scan = self.full_scan_last_index != self.tar_iter_without_port.p_sub_one;

        // 定义 开始结束的时间
        let start_time;
        let end_time;

        // 预扫描阶段
        {
            // 创建信息传递管道
            // 接收准备完成管道: 用于在接收线程准备好进行接收时,向主线程发送允许执行发送线程的信号
            // 接收关闭时间管道: 用于接收从主线程传递过来的接收线程关闭时间
            creat_channels!((recv_ready_sender, recv_ready_receiver, bool),(recv_close_time_sender, recv_close_time_receiver, i64));

            let full_scan_res;
            {
                // 完全扫描 接收线程  数据准备
                prepare_data!(self; start_ip, end_ip, tar_ip_num);
                prepare_data!(self; clone; base_conf, receiver_conf, probe, tar_ports);
                let sports = self.sender_conf.source_ports.clone();

                // 执行 完全扫描(预扫描)接收线程
                full_scan_res = thread::spawn(move || {
                    // 注意: 这里应该用 全部目标范围, 而不是只有预探测目标范围
                    let bit_map = BitMapV4Port::new(start_ip, end_ip, tar_ip_num, tar_ports);
                    PcapReceiver::pmap_full_scan_v4(0, base_conf, receiver_conf, probe, sports, bit_map,
                                                    recv_ready_sender, recv_close_time_receiver)
                });
            }

            // 只有接收线程准备完毕后，发送线程才能继续执行
            recv_ready!(recv_ready_receiver);

            // 获取 完全扫描的多线程任务分配列表
            let full_scan_tar_ranges = TarIterBaseConf::cycle_group_assign_targets_u64(self.full_scan_last_index, self.sender_conf.send_thread_num as u64);

            // 记录 开始发送的时间
            start_time = Local::now();

            // 执行 完全扫描 发送线程
            let mut full_scan_sender_threads = vec![];
            for target_range in full_scan_tar_ranges {

                // 发送线程 数据准备
                prepare_data!(self; clone; blocker, base_conf, sender_conf, probe, tar_ports);
                // 初始化 局部目标迭代器
                let target_iter = self.tar_iter_without_port.init(target_range.0, target_range.1);

                let full_scan_sender = thread::spawn(move || {
                    pmap_full_scan_send_v4(0, target_iter, blocker, probe, tar_ports, base_conf, sender_conf)
                });

                full_scan_sender_threads.push(full_scan_sender);
            }

            // 等待 发送线程 执行完毕
            wait_sender_threads!(full_scan_sender_threads; send_success, send_failed, blocked; {
                total_send_success += send_success;
                total_send_failed += send_failed;
                total_blocked += blocked;
            });

            // 计算终止时间 并向接收线程传递
            ending_the_receiving_thread!(self; recv_close_time_sender);

            // 处理接收线程得到的数据
            if let Ok(res) = full_scan_res.join() {

                // 完全扫描全局迭代器
                let full_scan_iter = self.tar_iter_without_port.init(0, self.full_scan_last_index);
                // 生成 有序目标端口列表
                let mut sorted_tar_ports = self.tar_ports.clone(); sorted_tar_ports.sort();

                if recommend_scan {     // 将完全扫描阶段的结果进行输出, 使用结果对概率相关图进行训练

                    let mut raw_graph = PmapGraph::new();

                    let (ip_count, pair_count) = full_scan_output_and_train_v4(full_scan_iter, &res, &sorted_tar_ports, &self.blocker, &mut out_mod, &mut raw_graph);

                    total_ip_count += ip_count;
                    total_pair_count += pair_count;

                    out_mod.close_output();
                    raw_graph.update_end();

                    graph = Arc::new(raw_graph);
                } else {        // 将完全扫描阶段的结果进行输出
                    let (ip_count, pair_count) = full_scan_output_v4(full_scan_iter, &res, &sorted_tar_ports, &self.blocker, &mut out_mod);

                    total_ip_count += ip_count;
                    total_pair_count += pair_count;

                    out_mod.close_output();
                    graph = Arc::new(PmapGraph::new_void());
                }
            } else {
                graph = Arc::new(PmapGraph::new_void());
            }
        }

        // 活跃端口推荐探测阶段
        if recommend_scan {

            // 状态库
            // 状态标签 -> 状态指针
            // 状态由 有序(从小到大)开放端口集合 生成, 如 开放端口集合为[3, 1, 2], 状态标签为 1,2,3
            let mut states_map:AHashMap<String, Arc<PmapState>> = AHashMap::new();

            // 生成 pmap迭代器 队列
            let mut pmap_iter_queue= create_pmap4_iter_queue(
                self.full_scan_last_index, self.tar_iter_without_port.p_sub_one, self.sender_conf.send_thread_num as u64, &self.tar_iter_without_port);

            let mut sent_port_count:u32 = 0;
            loop {
                // 在一个循环内, 所有待探测地址被探测一个端口

                // 如果  每个地址发送的端口数量(包含本轮次)  大于 预算时, 结束 推荐扫描
                sent_port_count += 1; if sent_port_count > self.budget { break }

                // 创建信息传递管道
                creat_channels!((recv_ready_sender, recv_ready_receiver, bool),(recv_close_time_sender, recv_close_time_receiver, i64));

                let recommend_scan_res;
                {
                    // 推荐扫描 接收线程 数据准备
                    prepare_data!(self; start_ip, end_ip, tar_ip_num);
                    prepare_data!(self; clone; base_conf, receiver_conf, probe);
                    let sports = self.sender_conf.source_ports.clone();

                    // 执行 推荐扫描 接收线程
                    recommend_scan_res = thread::spawn(move || {
                        // 初始化 位图记录器
                        let bit_map = BitMapV4::new(start_ip, end_ip, tar_ip_num);
                        PcapReceiver::pmap_recommend_scan_v4(0, base_conf, receiver_conf, probe, sports, bit_map,
                                                             recv_ready_sender, recv_close_time_receiver) });
                }

                // 只有接收线程准备完毕后，发送线程才能继续执行
                recv_ready!(recv_ready_receiver);

                // 执行 推荐扫描 发送线程
                let mut recommend_scan_sender_threads = vec![];
                for pmap_iter in pmap_iter_queue.into_iter() {

                    prepare_data!(self; clone; blocker, base_conf, sender_conf, probe);
                    let graph_ptr = graph.clone();

                    let recommend_scan_sender = thread::spawn(move || {
                        pmap_recommend_scan_send_v4_port(0, pmap_iter, blocker, probe, graph_ptr, base_conf, sender_conf)
                    });

                    recommend_scan_sender_threads.push(recommend_scan_sender);
                }

                // 等待 发送线程 执行完毕
                pmap_iter_queue = vec![];
                wait_sender_threads!(recommend_scan_sender_threads; send_success, send_failed, blocked, pmap_iter; {
                    // 接收迭代器队列
                        pmap_iter_queue.push(pmap_iter);

                        total_send_success += send_success;
                        total_send_failed += send_failed;
                        total_blocked += blocked;
                });

                // 计算终止时间 并向接收线程传递
                ending_the_receiving_thread!(self; recv_close_time_sender);

                // 处理接收线程得到的数据
                if let Ok(res) = recommend_scan_res.join() {
                    match Arc::get_mut(&mut graph) {

                        // 使用本轮探测结果对 地址信息, 状态库进行更新
                        Some(g_ptr) => { pmap_receive(res, g_ptr, &mut states_map, &mut pmap_iter_queue, &self.blocker); }

                        // 如果 获取概率相关图的可变指针失败
                        None => {   error!("{}", SYS.get_info("err", "get_graph_arc_failed"));  exit(1) }
                    }
                }
            }

            // 记录结束时间
            end_time = Local::now();
            // 清理 概率相关图
            drop(graph);
            // 清理 状态库
            drop(states_map);

            for pmap_iter in pmap_iter_queue.into_iter() {

                init_var!(u32; 0; ip_index);
                let cur_start_ip = pmap_iter.ipv4_guide_iter.start_ip;
                for ip_struct in pmap_iter.ip_map.into_iter() {

                    if ip_struct.open_ports.len() != 0 {

                        total_ip_count += 1;
                        total_pair_count += ip_struct.open_ports.len();

                        // 生成 端口字符串
                        let mut port_str = String::new();
                        for port in ip_struct.open_ports.into_iter() { port_str.push_str(&format!("{}|", port)); }
                        port_str.pop();

                        let out_line = vec![Ipv4Addr::from(cur_start_ip + ip_index).to_string(), port_str];
                        out_mod.writer_line(&out_line);
                    }

                    ip_index += 1;
                }
            }
            // 关闭输出
            out_mod.close_output();
        } else { end_time = Local::now(); }  // 记录结束时间

        // 探测 和 接收 执行完毕
        println!("{} {} {} {}", SYS.get_info("print", "send_finished"), total_send_success, total_send_failed, total_blocked);
        println!("{} {} {}", SYS.get_info("print", "pmap_scan_finished"), total_ip_count, total_pair_count);
        computing_time!(start_time, end_time; running_time);

        write_to_summary!(self; "PmapV4"; "result";
            [start_time, end_time, running_time, total_send_success, total_send_failed, total_blocked, total_ip_count, total_pair_count;]
        );
    }
}