use std::process::exit;
use std::thread;
use ahash::AHashSet;
use chrono::Local;
use log::{error, info};
use crate::{computing_time, creat_channels, ending_the_receiving_thread, init_var, prepare_data, recv_ready, wait_sender_threads, write_to_summary, SYS};
use crate::core::receiver::pcap::PcapReceiver;
use crate::core::sender::send_prefixes_v6_2;
use crate::modes::ModeMethod;
use crate::modes::v6::edge6::Edge6;
use crate::modules::output_modules::OutputMod;
use crate::modules::target_iterators::EdgeIter6;
use crate::tools::others::split::split_chains;

impl ModeMethod for Edge6 {
    fn execute(&self) {
        // 由目标前缀文件生成目标迭代器
        let mut edge_iter = EdgeIter6::new(&self.path, self.window_size, self.hop_limit);
        let prefix_len = edge_iter.pcs_list.len();

        // 定义扫描开始时间
        let start_time = Local::now();
        // 定义 接收线程, 发送线程 消息; 已经使用的总预算
        init_var!(u64; 0; total_send_success, total_send_failed);

        // 初始化 输出模块
        let mut out_mod = OutputMod::init(&self.receiver_conf.output_v6);

        // 所有探测到的响应点的集合
        let mut all_nodes:AHashSet<u128> = AHashSet::new();

        loop {

            // 如果已经成功发送的数量 大于等于 预算 就直接退出
            if total_send_success >= self.budget { break }

            let tars = edge_iter.gen_target(self.batch_size);
            if tars.is_empty() { break }

            // 创建信息传递管道
            creat_channels!((recv_ready_sender, recv_ready_receiver, bool),(recv_close_time_sender, recv_close_time_receiver, i64));

            // 执行接收线程
            let receiver_res;
            {
                prepare_data!(self; clone; base_conf, receiver_conf, probe);
                receiver_res = thread::spawn(move || {
                    PcapReceiver::run_topo_code_v6_vec(0, out_mod, base_conf, receiver_conf,
                                                       probe, all_nodes, prefix_len,
                                                       recv_ready_sender, recv_close_time_receiver, true)
                });
            }

            // 只有接收线程准备完毕后，发送线程才能继续执行
            recv_ready!(recv_ready_receiver);
           
            let targets_list = split_chains(tars, self.sender_conf.send_thread_num);

            let mut sender_threads = vec![];
            for tar_addrs_per in targets_list.into_iter() {
                prepare_data!(self; clone; base_conf, sender_conf, probe);

                sender_threads.push(thread::spawn(move || {
                    send_prefixes_v6_2(0, tar_addrs_per, probe, base_conf, sender_conf)
                }));
            }

            // 等待发送线程执行完成, 并收集汇总从各个发送线程传递回来的信息
            wait_sender_threads!(sender_threads; send_success, send_failed;{
                total_send_success += send_success;
                total_send_failed += send_failed;
            });

            // 计算终止时间 并向接收线程传递
            ending_the_receiving_thread!(self; recv_close_time_sender);

            // 等待接收线程按照预定时间关闭
            if let Ok((cur_all_nodes, recorder, output)) = receiver_res.join() {
                all_nodes = cur_all_nodes;
                out_mod = output;

                // 更新所有前缀的 reward
                edge_iter.update_rewards(recorder);

            } else { error!("{}", SYS.get_info("err", "recv_thread_err")); exit(1) }

            // 当前轮次结束后打印 当前信息
            let all_nodes_len = all_nodes.len();    let hit_rate = (all_nodes_len as f64) / (total_send_success as f64);
            info!("{} {}% {} {} {}", SYS.get_info("print", "ipv6_edge_info"), hit_rate * 100.0, all_nodes_len, total_send_success, total_send_failed);
        }

        // 计算 结束时间 和 格式化后的运行时间 并显示
        computing_time!(start_time; end_time, running_time);
        
        let all_nodes_len = all_nodes.len();
        let hit_rate = (all_nodes_len as f64) / (total_send_success as f64);
        info!("{} {}% {} {} {}", SYS.get_info("print", "ipv6_edge_info"), hit_rate * 100.0, all_nodes_len, total_send_success, total_send_failed);

        // 输出到记录文件
        write_to_summary!(self; "Edge6"; "result";
            [start_time, end_time, running_time, hit_rate, all_nodes_len, total_send_success, total_send_failed;]
        );
    }
}