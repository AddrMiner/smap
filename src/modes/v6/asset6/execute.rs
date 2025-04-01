use std::process::exit;
use std::thread;
use ahash::{AHashMap, AHashSet};
use chrono::Local;
use log::{error, info, trace};
use crate::modes::ModeMethod;
use crate::modes::v6::asset6::Asset6;
use crate::{computing_time, creat_channels, ending_the_receiving_thread, init_var, prepare_data, recv_ready, wait_sender_threads, write_to_summary, SYS};
use crate::core::receiver::pcap::PcapReceiver;
use crate::core::sender::send_v6_code_port_vec;
use crate::modules::output_modules::OutputMod;
use crate::modules::target_iterators::{IPv6AliaChecker, IPv6PortSpaceTree};
use crate::tools::others::split::split_chains;

impl ModeMethod for Asset6 {
    fn execute(&self) {

        // 实例化空间树
        let mut space_tree = self.addr_port_space_tree.clone();
        space_tree.init_density_tree();
        info!("{}", SYS.get_info("info", "ipv6_space_tree_instantiation"));

        // 定义扫描开始时间
        let start_time = Local::now();
        // 定义 接收线程, 发送线程 消息; 已经使用的总预算
        init_var!(u64; 0; total_send_success, total_send_failed, total_active_num, total_used_budget, all_sent, all_failed);

        // 初始化 输出模块
        let mut out_mod = OutputMod::init(&self.receiver_conf.output_v6);
        
        // 存放所有已知的别名前缀
        let mut aliased_prefixes:AHashSet<u64> = AHashSet::new();
        
        // 保存所有 被发现的地址 和 地址对应的开放端口数量
        let mut open_addrs_ports:AHashMap<u128, u16> = AHashMap::new();

        let mut count = 0u32;
        loop {

            count += 1;

            // 生成 目标集
            let targets: Vec<(Vec<u8>, u16, u128)>;
            {
                info!("{} {}", SYS.get_info("info", "cur_round"), count);
                let cur_budget = self.batch_size;

                loop {
                    let cur_tars = space_tree.gen_addrs(cur_budget, &aliased_prefixes, &open_addrs_ports, self.max_port_num);
                    if !cur_tars.is_empty(){
                        targets = cur_tars;
                        break
                    }
                    space_tree.update_tree(vec![0u64; space_tree.cur_extra_region_num]);
                }

                total_used_budget += targets.len() as u64;
            }

            info!("{} {}", SYS.get_info("info", "start_scan"), targets.len());

            // 创建信息传递管道
            creat_channels!((recv_ready_sender, recv_ready_receiver, bool),(recv_close_time_sender, recv_close_time_receiver, i64));

            // 执行接收线程
            let receiver_res;
            {
                let addrs_len = targets.len();
                let sports = self.sender_conf.source_ports.clone();
                let port_scan_flag = space_tree.port_scan_flag;
                let region_len = space_tree.cur_extra_region_num as u32;
                let max_port_num = self.max_port_num;
                prepare_data!(self; clone; base_conf, receiver_conf, probe);

                receiver_res = thread::spawn(move || {
                    PcapReceiver::space_tree_run_v6_port_vec(0, base_conf, receiver_conf, open_addrs_ports, max_port_num,
                                                             probe, addrs_len, sports, aliased_prefixes, port_scan_flag, region_len,
                                                        recv_ready_sender, recv_close_time_receiver)
                });
            }

            // 只有接收线程准备完毕后，发送线程才能继续执行
            recv_ready!(recv_ready_receiver);

            // 执行发送线程
            let tar_addrs_list = split_chains(targets, self.sender_conf.send_thread_num);
            let mut sender_threads = vec![];
            for tar_addrs_per in tar_addrs_list.into_iter() {
                prepare_data!(self; clone; base_conf, sender_conf, probe);

                sender_threads.push(thread::spawn(move || {
                    send_v6_code_port_vec(0, tar_addrs_per, probe, base_conf, sender_conf)
                }));
            }

            // 等待发送线程执行完成, 并收集汇总从各个发送线程传递回来的信息
            wait_sender_threads!(sender_threads; send_success, send_failed;{
                total_send_success += send_success;
                total_send_failed += send_failed;
                all_sent += send_success;
                all_failed += send_failed;
            });

            // 计算终止时间 并向接收线程传递
            ending_the_receiving_thread!(self; recv_close_time_sender);

            // 等待接收线程按照预定时间关闭
            let cur_records = if let Ok((records, aliased_prefixes_, open_addrs_ports_)) = receiver_res.join() {
                aliased_prefixes = aliased_prefixes_;
                open_addrs_ports = open_addrs_ports_;
                records
            } else {
                error!("{}", SYS.get_info("err", "recv_thread_err")); exit(1)
            };

            // 如果记录不为空
            if !cur_records.is_empty() {

                if self.aliased_prefixes_check {
                    // 取得 别名前缀列表, 别名探测目标
                    let (aliased_check_prefixes, aliased_check_targets) = space_tree.gen_aliased_check_targets(&cur_records);

                    // 创建信息传递管道
                    creat_channels!((recv_ready_sender, recv_ready_receiver, bool),(recv_close_time_sender, recv_close_time_receiver, i64));

                    // 执行接收线程
                    let aliased_check_receiver_res;
                    {
                        let addrs_len = aliased_check_targets.len() / 16 + 1;
                        let aliased_prefixes_len = aliased_check_prefixes.len();
                        let sports = self.sender_conf.source_ports.clone();
                        let aliased_scan_flag = space_tree.aliased_scan_flag;
                        prepare_data!(self; clone; base_conf, receiver_conf, probe);

                        aliased_check_receiver_res = thread::spawn(move || {
                            PcapReceiver::asset_aliased_check_scan(0, base_conf, receiver_conf,
                                                                   probe, addrs_len, sports, aliased_prefixes_len, aliased_scan_flag,
                                                                   recv_ready_sender, recv_close_time_receiver)
                        });
                    }

                    // 只有接收线程准备完毕后，发送线程才能继续执行
                    recv_ready!(recv_ready_receiver);

                    // 执行发送线程
                    let tar_addrs_list = split_chains(aliased_check_targets, self.sender_conf.send_thread_num);
                    let mut sender_threads = vec![];
                    for tar_addrs_per in tar_addrs_list.into_iter() {
                        prepare_data!(self; clone; base_conf, sender_conf, probe);

                        sender_threads.push(thread::spawn(move || {
                            send_v6_code_port_vec(0, tar_addrs_per, probe, base_conf, sender_conf)
                        }));
                    }

                    // 等待发送线程执行完成, 并收集汇总从各个发送线程传递回来的信息
                    wait_sender_threads!(sender_threads; send_success, send_failed;{
                        all_sent += send_success;
                        all_failed += send_failed;
                    });

                    // 计算终止时间 并向接收线程传递
                    ending_the_receiving_thread!(self; recv_close_time_sender);

                    // 等待接收线程按照预定时间关闭
                    if let Ok(aliased_check_res) = aliased_check_receiver_res.join() {
                        // 得到当前轮次的目标中对应的别名前缀
                        let cur_aliased_prefixes = space_tree.parse_aliased_result(aliased_check_res, aliased_check_prefixes);
                        // 根据别名前缀集合清理记录信息并更新空间树
                        let (region_recorder, cur_act_num) = IPv6PortSpaceTree::clear_and_print_records(&cur_aliased_prefixes, &mut open_addrs_ports, self.max_port_num, cur_records, &mut out_mod, space_tree.cur_extra_region_num);
                        // 将当前轮次的别名前缀向总别名前缀集合并
                        aliased_prefixes.extend(cur_aliased_prefixes);

                        info!("{} {}", SYS.get_info("info", "cur_active_num"),cur_act_num);
                        total_active_num += cur_act_num;
                        space_tree.update_tree(region_recorder);
                    } else {
                        error!("{}", SYS.get_info("err", "recv_thread_err")); exit(1)
                    };
                } else {
                    // 如果不开启别名检查
                    let (region_recorder, cur_act_num) = IPv6PortSpaceTree::print_records(cur_records, &mut open_addrs_ports, self.max_port_num, &mut out_mod, space_tree.cur_extra_region_num);
                    info!("{} {}", SYS.get_info("info", "cur_active_num"),cur_act_num);
                    total_active_num += cur_act_num;
                    space_tree.update_tree(region_recorder);
                }
            } else {
                info!("{} {}", SYS.get_info("info", "cur_active_num"), 0);
                space_tree.update_tree(vec![0u64; space_tree.cur_extra_region_num]);
            }
            if total_used_budget >= self.budget { break }

            // 改变扫描标识字段
            space_tree.change_scan_flag();
        }

        // 计算 结束时间 和 格式化后的运行时间 并显示
        computing_time!(start_time; end_time, running_time);
        
        
        if let Some(aliased_prefixes_path) = space_tree.aliased_prefixes_path {
            IPv6AliaChecker::save_aliased_prefixes_64_records(&aliased_prefixes_path, aliased_prefixes);
        }

        // 计算命中率
        let hit_rate = (total_active_num as f64) / (total_send_success as f64);

        // 终端显示结果
        println!("{} {}% {} {} {}", SYS.get_info("print", "ipv6_addrs_gen_finished"), hit_rate * 100.0, total_active_num, total_send_success, total_send_failed);

        // 计算命中率
        let a_hit_rate = (total_active_num as f64) / (all_sent as f64);
        trace!("{} {}% {} {} {}", SYS.get_info("print", "ipv6_addrs_gen_finished_con_aliased"), a_hit_rate * 100.0, total_active_num, all_sent, all_failed);

        write_to_summary!(self; "Asset6"; "result";
            [start_time, end_time, running_time, hit_rate, total_active_num, total_send_success, total_send_failed;]
        );
        
    }
}