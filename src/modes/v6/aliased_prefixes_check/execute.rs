use std::process::exit;
use std::thread;
use ahash::AHashSet;
use chrono::Local;
use log::{error, info};
use crate::{computing_time, creat_channels, ending_the_receiving_thread, init_var, prepare_data, recv_ready, wait_sender_threads, write_to_summary, SYS};
use crate::core::receiver::pcap::PcapReceiver;
use crate::core::sender::send_v6_u32code_vec;
use crate::modes::ModeMethod;
use crate::modes::v6::aliased_prefixes_check::IPv6AliasedCheck;
use crate::modules::output_modules::OutputMod;
use crate::tools::others::split::split_chains;

impl ModeMethod for IPv6AliasedCheck {
    fn execute(&self) {

        // 初始化别名前缀检查器
        let mut checker = self.ipv6_aliased_checker.clone();
        checker.init();
        // 总前缀数量
        let total_prefixes_len = checker.prefixes.len();
        // 别名前缀集合 (按总前缀数量的百分之一分配空间)
        let mut alia_prefixes:Vec<u128> = Vec::with_capacity(((total_prefixes_len as f64) * 0.01) as usize);

        // 初始化 输出模块
        let mut out_mod = OutputMod::init(&self.receiver_conf.output_v6);
        out_mod.writer_line(&vec![String::from("ipv6_aliased_prefixes")]);

        // 记录 开始发送的时间
        let start_time = Local::now();
        init_var!(u64; 0; total_send_success, total_send_failed, toal_act_addrs_len);
        'scan:loop {
            // 生成探测目标
            let cur_targets = checker.gen_targets();
            // 当前探测目标数量
            let cur_targets_len = cur_targets.len();
            if cur_targets_len <= 0 { break 'scan }
            // 当前探测前缀数量
            let cur_tar_prefixes_len = checker.cur_prefixes.len();

            // 创建信息传递管道
            creat_channels!((recv_ready_sender, recv_ready_receiver, bool),(recv_close_time_sender, recv_close_time_receiver, i64));

            // 执行接收线程
            let receiver_res;
            {
                prepare_data!(self; clone; base_conf, receiver_conf, probe);
                receiver_res = thread::spawn(move || {
                    PcapReceiver::run_alia_v6_vec(0, base_conf, receiver_conf, probe, cur_targets_len, cur_tar_prefixes_len,
                                                  recv_ready_sender, recv_close_time_receiver)
                });
            }

            // 只有接收线程准备完毕后，发送线程才能继续执行
            recv_ready!(recv_ready_receiver);

            // 执行发送线程
            let tar_addrs_list = split_chains(cur_targets, self.sender_conf.send_thread_num);
            let mut sender_threads = vec![];
            for tar_addrs_per in tar_addrs_list.into_iter() {
                prepare_data!(self; clone; base_conf, sender_conf, probe);

                sender_threads.push(thread::spawn(move || {
                    send_v6_u32code_vec(0, tar_addrs_per, probe, base_conf, sender_conf)
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
            if let Ok((act_addrs_len, recorder)) = receiver_res.join() {
                // 处理接收线程返回的信息
                
                // 分析, 收集, 输出  别名前缀
                checker.get_alia_prefixes(recorder, &mut alia_prefixes, &mut out_mod);
                
                // 记录 唯一活跃地址数量
                toal_act_addrs_len += act_addrs_len as u64;
            } else { error!("{}", SYS.get_info("err", "recv_thread_err"));exit(1) }
        }
        
        // 计算 结束时间 和 格式化后的运行时间 并显示
        computing_time!(start_time; end_time, running_time);
        
        // 别名前缀总量
        let aliased_prefixes_len = alia_prefixes.len();
        
        // 判断并输出别名地址
        let mut aliased_addrs_len = 0;
        if self.output_alia_addrs {
            let alia_prefixes_set:AHashSet<u128> = alia_prefixes.into_iter().collect();
            aliased_addrs_len = checker.get_alia_addrs(alia_prefixes_set, &mut out_mod);
        }
        
        // 输出模块关闭输出, 刷新缓冲区
        out_mod.close_output();

        info!("{} {} {} {} {} {} {}", SYS.get_info("info", "alia_checker_recv_finished"),
                    aliased_prefixes_len, total_prefixes_len, aliased_addrs_len, total_send_success, total_send_failed, toal_act_addrs_len);

        write_to_summary!(self; "IPv6AliasedChecker"; "result"; [start_time, end_time, running_time, total_send_success, total_send_failed, aliased_prefixes_len, total_prefixes_len, toal_act_addrs_len;]);
        
    }
}