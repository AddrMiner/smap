use std::process::exit;
use std::thread;
use chrono::Local;
use log::{error, info};
use crate::modes::ModeMethod;
use crate::modes::v6::space_tree::new::SpaceTreeType;
use crate::modes::v6::space_tree::SpaceTree6;
use crate::{computing_time, creat_channels, ending_the_receiving_thread, init_var, prepare_data, recv_ready, SYS, wait_sender_threads, write_to_summary};
use crate::core::receiver::pcap::PcapReceiver;
use crate::core::sender::send_v6_vec;
use crate::modules::output_modules::OutputMod;
use crate::tools::others::split::split_chains;

impl ModeMethod for SpaceTree6 {
    fn execute(&self) {

        // 实例化空间树
        let mut space_tree = self.space_tree.clone();
        info!("{}", SYS.get_info("info", "ipv6_space_tree_instantiation"));
        match self.space_tree_type {
            // 生成 密度空间树
            SpaceTreeType::DENSITY => space_tree.init_density_tree(),
        };

        // 定义扫描开始时间
        let start_time = Local::now();
        // 定义 接收线程, 发送线程 消息; 已经使用的总预算
        init_var!(u64; 0; total_send_success, total_send_failed, total_active_num, total_used_budget);

        // 初始化 输出模块
        let mut out_mod = OutputMod::init(&self.receiver_conf.output_v6);

        let mut count = 0u32;
        loop {
            
            count += 1;
            
            let mut end_flag:bool = false;
            if total_used_budget + self.batch_size >= self.budget {
                end_flag = true;
            }
            
            // 生成 目标地址集
            let tar_addrs: Vec<(u16, u128)>;
            {
                info!("{} {}", SYS.get_info("info", "ipv6_addrs_gen_round"), count);
                let cur_budget = if end_flag { self.budget - total_used_budget } else { self.batch_size };
                
                loop {
                    let cur_tar_addrs = space_tree.gen_addrs(cur_budget);
                    if cur_tar_addrs.len() != 0 {
                        tar_addrs = cur_tar_addrs;
                        break
                    }
                    space_tree.update_tree(vec![0u64; space_tree.cur_extra_region_num]);
                }
                
                total_used_budget += tar_addrs.len() as u64;
            }

            info!("{} {}", SYS.get_info("info", "start_scan"), tar_addrs.len());

            // 创建信息传递管道
            creat_channels!((recv_ready_sender, recv_ready_receiver, bool),(recv_close_time_sender, recv_close_time_receiver, i64));

            // 执行接收线程
            let receiver_res;
            {
                let addrs_len = tar_addrs.len();
                let regions_len = space_tree.cur_extra_region_num;
                prepare_data!(self; clone; base_conf, receiver_conf, probe);

                receiver_res = thread::spawn(move || {
                    PcapReceiver::space_tree_run_v6_vec(0, out_mod, base_conf, receiver_conf, probe, addrs_len, regions_len,
                                                        recv_ready_sender, recv_close_time_receiver)
                });
            }

            // 只有接收线程准备完毕后，发送线程才能继续执行
            recv_ready!(recv_ready_receiver);

            // 执行发送线程
            let tar_addrs_list = split_chains(tar_addrs, self.sender_conf.send_thread_num);
            let mut sender_threads = vec![];
            for tar_addrs_per in tar_addrs_list.into_iter() {
                prepare_data!(self; clone; base_conf, sender_conf, probe);

                sender_threads.push(thread::spawn(move || {
                      send_v6_vec(0, tar_addrs_per, probe, base_conf, sender_conf)
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
            if let Ok((cur_active_num, region_recorder, output)) = receiver_res.join() {
                info!("{} {}", SYS.get_info("info", "ipv6_addrs_gen_round_active_num"),cur_active_num);
                total_active_num += cur_active_num as u64;
                space_tree.update_tree(region_recorder);
                out_mod = output;
            } else {
                error!("{}", SYS.get_info("err", "recv_thread_err")); exit(1)
            }
            
            if end_flag {
                break
            }
        }

        // 计算 结束时间 和 格式化后的运行时间 并显示
        computing_time!(start_time; end_time, running_time);

        // 计算命中率
        let hit_rate = (total_active_num as f64) / (total_send_success as f64);
        
        // 终端显示结果
        println!("{} {}% {} {} {}", SYS.get_info("print", "ipv6_addrs_gen_finished"), hit_rate * 100.0, total_active_num, total_send_success, total_send_failed);
        
        write_to_summary!(self; "SpaceTree6"; "result";
            [start_time, end_time, running_time, hit_rate, total_active_num, total_send_success, total_send_failed;]
        );
    }
}