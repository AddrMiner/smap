use std::process::exit;
use std::thread;
use ahash::AHashSet;
use chrono::Local;
use log::{error, info};
use crate::modes::ModeMethod;
use crate::modules::output_modules::OutputMod;
use crate::modules::target_iterators::Ipv6VecDoubleTree;
use crate::{computing_time, creat_channels, ending_the_receiving_thread, init_var, prepare_data, recv_ready, SYS, wait_sender_threads, write_to_summary};
use crate::core::receiver::pcap::PcapReceiver;
use crate::core::sender::send_prefixes_v6;
use crate::modes::v6::prefix_fixed_tree::{PrefixFixedTree6, SplitNodeSelectType};
use crate::tools::others::split::split_chains;


impl ModeMethod for PrefixFixedTree6 {
    fn execute(&self) {

        // 实例化前缀空间树
        info!("{}", SYS.get_info("info", "ipv6_space_tree_instantiation"));
        let mut prefix_tree = self.prefix_tree.clone();
        prefix_tree.init_hier_tree();

        // 所有探测到的响应点的集合
        let mut all_nodes:AHashSet<u128> = AHashSet::new();

        // 初始化 DoubleTree 结构体
        let mut double_tree_struct = Ipv6VecDoubleTree::new(self.initial_ttl, self.gap_limit, self.max_ttl, self.min_target_num);

        // 初始化 输出模块
        let mut out_mod = OutputMod::init(&self.receiver_conf.output_v6);

        // 定义扫描开始时间
        let start_time = Local::now();

        // 定义 接收线程, 发送线程 消息; 已经使用的总预算
        init_var!(u64; 0; total_send_success, total_send_failed);

        let mut round_count = 0usize;
        'total:loop {

            round_count += 1;
            info!("{} {}", SYS.get_info("info", "cur_round"), round_count);

            if round_count == 1 {
                // 生成 初始节点队列, 并获得初始探测列表
                let (target_addrs, addr_to_seq) = prefix_tree.init_queue();
                info!("{} {} {} {} {} {}", SYS.get_info("info", "start_scan"), target_addrs.len(), SYS.get_info("info", "cur_no_split_node_num"), 
                    prefix_tree.node_queue.len(), SYS.get_info("info", "cur_split_node_num"), prefix_tree.cur_tar_node_queue.len());
                double_tree_struct.set_targets(target_addrs, addr_to_seq);
            } else {
                let (target_addrs, addr_to_seq) = prefix_tree.gen_targets();
                info!("{} {} {} {} {} {}", SYS.get_info("info", "start_scan"), target_addrs.len(), SYS.get_info("info", "cur_no_split_node_num"), 
                    prefix_tree.node_queue.len(), SYS.get_info("info", "cur_split_node_num"), prefix_tree.cur_tar_node_queue.len());
                double_tree_struct.set_targets(target_addrs, addr_to_seq);
            }

            let mut topo_round_count = 0usize;
            let mut targets = vec![];
            'topo:loop {

                topo_round_count += 1;

                // 第一次生成探测目标
                if topo_round_count == 1 { targets = double_tree_struct.first_get_targets(); }

                info!("{} {} {} {}", SYS.get_info("info", "topo_round"), topo_round_count, SYS.get_info("info", "tar_num"), targets.len());

                // 创建信息传递管道
                creat_channels!((recv_ready_sender, recv_ready_receiver, bool),(recv_close_time_sender, recv_close_time_receiver, i64));

                // 执行接收线程
                let receiver_res;
                {
                    let sports = self.sender_conf.source_ports.clone();
                    prepare_data!(self; clone; base_conf, receiver_conf, probe);
                    receiver_res = thread::spawn(move || {
                        PcapReceiver::prefix_tree_scan_v6(0, out_mod, double_tree_struct, all_nodes,
                                                          base_conf, receiver_conf, probe, sports, recv_ready_sender, recv_close_time_receiver)
                    });
                }

                // 只有接收线程准备完毕后，发送线程才能继续执行
                recv_ready!(recv_ready_receiver);

                // 执行发送线程
                let targets_list = split_chains(targets, self.sender_conf.send_thread_num);
                let mut sender_threads = vec![];
                for tar_addrs_per in targets_list.into_iter() {
                    prepare_data!(self; clone; base_conf, sender_conf, probe);

                    sender_threads.push(thread::spawn(move || {
                        send_prefixes_v6(0, tar_addrs_per, probe, base_conf, sender_conf)
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
                if let Ok((cur_double_tree_struct, cur_all_nodes, output, new_targets)) = receiver_res.join() {
                    double_tree_struct = cur_double_tree_struct;
                    all_nodes = cur_all_nodes;
                    out_mod = output;

                    // 如果新生成的探测目标为空, 说明本轮拓扑探测已经结束
                    if new_targets.is_empty() { break 'topo }

                    targets = new_targets;
                } else { error!("{}", SYS.get_info("err", "recv_thread_err")); exit(1) }
            }

            // 更新前缀树
            match self.split_node_select_type {
                SplitNodeSelectType::CASCADE => if prefix_tree.update_tree(&double_tree_struct.reward_used){ break },
                SplitNodeSelectType::INDEPENDENT => if prefix_tree.update_tree_independent(&double_tree_struct.reward_used) { break }
            }

            // 如果已经发送的总数据包数量超过预算, 结束整个探测任务
            if total_send_success >= self.budget { break 'total }

            // 当前轮次结束后打印 当前信息
            let all_nodes_len = all_nodes.len();    let hit_rate = (all_nodes_len as f64) / (total_send_success as f64);
            info!("{} {}% {} {} {}", SYS.get_info("print", "ipv6_prefix_tree_cur_info"), hit_rate * 100.0, all_nodes_len, total_send_success, total_send_failed);
        }

        // 计算 结束时间 和 格式化后的运行时间 并显示
        computing_time!(start_time; end_time, running_time);

        // 计算 发现的拓扑节点地址总量 / 发送的总数据包数量
        let all_nodes_len = all_nodes.len(); let hit_rate = (all_nodes_len as f64) / (total_send_success as f64);
        info!("{} {}% {} {} {}", SYS.get_info("print", "ipv6_prefixes_gen_finished"), hit_rate * 100.0, all_nodes_len, total_send_success, total_send_failed);

        // 输出到记录文件
        write_to_summary!(self; "PrefixTree6"; "result";
            [start_time, end_time, running_time, hit_rate, all_nodes_len, total_send_success, total_send_failed;]
        );
    }
}