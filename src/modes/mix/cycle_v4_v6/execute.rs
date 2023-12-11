use crate::SYS;
use std::process::exit;
use std::sync::mpsc;
use std::thread;
use chrono::{Local, Utc};
use log::error;
use crate::core::receiver::pcap::PcapReceiver;
use crate::core::sender::{send_cycle_group_v4, send_cycle_group_v6};
use crate::modes::mix::cycle_v4_v6::CycleV4V6;
use crate::modes::ModeMethod;
use crate::tools::file::write_to_file::write_record;
use crate::tools::others::time::get_fmt_duration;

impl ModeMethod for CycleV4V6 {
    fn execute(&self) {

        // 创建信息传递管道
        let (recv_ready_sender, recv_ready_receiver) = mpsc::channel();
        let (recv_close_time_sender, recv_close_time_receiver) = mpsc::channel();

        // 执行接收线程
        let receiver_res;
        {
            let tar_num_v4 = self.tar_num_v4 as usize;
            let tar_num_v6 = self.tar_num_v6 as usize;

            let base_conf = self.base_conf.clone();
            let receiver_conf = self.receiver_conf.clone();
            let probe_v4 = self.probe_v4.clone();
            let probe_v6 = self.probe_v6.clone();

            let sports = self.sender_conf.source_ports.clone();

            receiver_res = thread::spawn(move || {
                PcapReceiver::run_v4_v6(0, base_conf, receiver_conf, probe_v4,probe_v6, sports,
                                        tar_num_v4, tar_num_v6,
                                     recv_ready_sender, recv_close_time_receiver)
            });
        }

        // 只有接收线程准备完毕后，发送线程才能继续执行
        if let Err(_) = recv_ready_receiver.recv() {
            error!("{}", SYS.get_info("err", "recv_ready_receive_failed"));
            exit(1)
        }

        // 记录 开始发送的时间
        let start_time = Local::now();

        // 执行 ipv4 发送线程
        let mut sender_threads = vec![];
        for assigned_ranges in self.assigned_target_range_v4.iter() {

            let assigned_ranges = assigned_ranges.clone();
            let tar_iters_v4 = self.target_iters_v4.clone();

            let base_conf = self.base_conf.clone();
            let sender_conf = self.sender_conf.clone();
            let probe_v4 = self.probe_v4.clone();
            let blocker_v4 = self.blocker_v4.clone();
            let v4_ranges = self.v4_ranges.clone();

            let sender_thread = thread::spawn(move || {

                let mut send_success:u64 = 0;
                let mut send_failed:u64 = 0;
                let mut blocked:u64 = 0;

                for (index, assigned_range) in assigned_ranges.into_iter().enumerate() {
                    if assigned_range.2 != 0 {
                        // 如果目标范围 数量不为 0

                        // 使用 目标范围起始位置 进一步优化约束范围
                        let blocker_v4 = blocker_v4.gen_local_constraints(v4_ranges[index].0, v4_ranges[index].1);

                        let probe_v4 = probe_v4.clone();
                        let base_conf = base_conf.clone();
                        let sender_conf = sender_conf.clone();

                        let tar_iter_v4 = tar_iters_v4[index].init(assigned_range.0, assigned_range.1);

                        let res = send_cycle_group_v4(0, tar_iter_v4, 0,        // 局部目标数量设为0, 使速率控制器以全局速率发送
                                            blocker_v4,probe_v4, None, base_conf, sender_conf);

                        send_success += res.0;
                        send_failed += res.1;
                        blocked += res.2;
                    }
                }
                (send_success, send_failed, blocked)
            });
            sender_threads.push(sender_thread);
        }

        // 执行 ipv6 发送线程
        for assigned_ranges in self.assigned_target_range_v6.iter() {

            let assigned_ranges = assigned_ranges.clone();
            let tar_iters_v6 = self.target_iters_v6.clone();

            let base_conf = self.base_conf.clone();
            let sender_conf = self.sender_conf.clone();
            let probe_v6 = self.probe_v6.clone();
            let blocker_v6 = self.blocker_v6.clone();
            let v6_ranges = self.v6_ranges.clone();

            let sender_thread = thread::spawn(move || {

                let mut send_success:u64 = 0;
                let mut send_failed:u64 = 0;
                let mut blocked:u64 = 0;

                for (index, assigned_range) in assigned_ranges.into_iter().enumerate() {
                    if assigned_range.2 != 0 {
                        // 如果目标范围 数量不为 0

                        let blocker_v6 = blocker_v6.gen_local_constraints(v6_ranges[index].0, v6_ranges[index].1);

                        let probe_v6 = probe_v6.clone();
                        let base_conf = base_conf.clone();
                        let sender_conf = sender_conf.clone();

                        let tar_iter_v6 = tar_iters_v6[index].init(assigned_range.0, assigned_range.1);

                        let res = send_cycle_group_v6(0, tar_iter_v6, 0,
                                                      blocker_v6,probe_v6, None, base_conf, sender_conf);

                        send_success += res.0;
                        send_failed += res.1;
                        blocked += res.2;
                    }
                }
                (send_success, send_failed, blocked)
            });
            sender_threads.push(sender_thread);
        }

        // 等待发送线程执行完成, 并收集汇总从各个发送线程传递回来的信息
        let mut total_send_success:u64 = 0;
        let mut total_send_failed:u64 = 0;
        let mut total_blocked:u64 = 0;
        for sender_thread in sender_threads {
            let sender_res = sender_thread.join();

            if let Ok((send_success, send_failed, blocked)) = sender_res {
                total_send_success += send_success;
                total_send_failed += send_failed;
                total_blocked += blocked;
            } else {
                error!("{}", SYS.get_info("err", "send_thread_err"));
                exit(1)
            }
        }

        println!("{} {} {} {}", SYS.get_info("print", "send_finished"), total_send_success, total_send_failed, total_blocked);

        // 计算终止时间 并向接收线程传递
        let end_time = Utc::now().timestamp() + self.sender_conf.cool_seconds;
        if let Err(_) = recv_close_time_sender.send(end_time){
            // 向接收线程发送终止时间失败
            error!("{}", SYS.get_info("err","send_recv_close_time_failed"));
            exit(1)
        }

        // 等待接收线程按照预定时间关闭
        if let Ok((receiver_info_v4, receiver_info_v6)) = receiver_res.join() {
            // 处理接收线程返回的信息

            // 记录结束发送的时间
            let end_time = Local::now();
            let running_time = (end_time - start_time).num_seconds();
            let running_time = get_fmt_duration(running_time, SYS.get_info("print", "running_time_pattern"));

            println!("{} {} {} {} {} {} {}", SYS.get_info("print", "recv_finished_mix"),
                     receiver_info_v4.success_total, receiver_info_v4.repeat_total, receiver_info_v4.failed_total,
                     receiver_info_v6.success_total, receiver_info_v6.repeat_total, receiver_info_v6.failed_total);
            println!("{} {}", SYS.get_info("print", "show_running_time"), running_time);

            if let Some(summary_path) = &self.base_conf.summary_file {
                // 将所有信息写入记录文件

                let header = vec!["start_time", "end_time", "running_time",
                                  "send_success", "send_failed", "send_blocked",

                                  "receive_success_v4", "receive_failed_v4",
                                  "receive_repeat", "receive_validation_passed_v4",
                                  "receive_validation_failed_v4",

                                  "receive_success_v6", "receive_failed_v6",
                                  "receive_repeat_v6", "receive_validation_passed_v6",
                                  "receive_validation_failed_v6"];
                let val = vec![ start_time.to_string(), end_time.to_string(), running_time,
                                total_send_success.to_string(), total_send_failed.to_string(), total_blocked.to_string(),

                                receiver_info_v4.success_total.to_string(), receiver_info_v4.failed_total.to_string(),
                                receiver_info_v4.repeat_total.to_string(), receiver_info_v4.validation_passed.to_string(),
                                receiver_info_v4.validation_failed.to_string(),

                                receiver_info_v6.success_total.to_string(), receiver_info_v6.failed_total.to_string(),
                                receiver_info_v6.repeat_total.to_string(), receiver_info_v6.validation_passed.to_string(),
                                receiver_info_v6.validation_failed.to_string(), ];

                write_record("CycleV4V6", "result", summary_path, header, val);
            }
        } else {
            error!("{}", SYS.get_info("err", "recv_thread_err"));
            exit(1)
        }
    }
}