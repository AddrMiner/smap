use crate::{computing_time, creat_channels, ending_the_receiving_thread, init_var, prepare_data, recv_ready, SYS, wait_sender_threads, write_to_summary};
use std::process::exit;
use std::thread;
use bitvec::macros::internal::funty::Fundamental;
use chrono::{Local};
use log::error;
use crate::core::receiver::pcap::PcapReceiver;
use crate::core::sender::{send_v4_port, send_v6_port};
use crate::modes::mix::cycle_v4_v6::CycleV4V6;
use crate::modes::ModeMethod;

impl ModeMethod for CycleV4V6 {
    fn execute(&self) {

        // 创建信息传递管道
        creat_channels!((recv_ready_sender, recv_ready_receiver, bool),(recv_close_time_sender, recv_close_time_receiver, i64));

        // 执行接收线程
        let receiver_res;
        {
            prepare_data!(self; as_usize; tar_num_v4, tar_num_v6);
            prepare_data!(self; clone; base_conf, receiver_conf, probe_v4, probe_v6);
            let sports = self.sender_conf.source_ports.clone();

            receiver_res = thread::spawn(move || {
                PcapReceiver::run_v4_v6(0, base_conf, receiver_conf, probe_v4,probe_v6, sports, tar_num_v4, tar_num_v6,
                                     recv_ready_sender, recv_close_time_receiver)
            });
        }

        // 只有接收线程准备完毕后，发送线程才能继续执行
        recv_ready!(recv_ready_receiver);

        // 记录 开始发送的时间
        let start_time = Local::now();

        // 执行 ipv4 发送线程
        let mut sender_threads = vec![];
        for assigned_ranges in self.assigned_target_range_v4.iter() {

            let assigned_ranges = assigned_ranges.clone();
            prepare_data!(self; ttl);
            prepare_data!(self; clone; base_conf, sender_conf, probe_v4, blocker_v4, v4_ranges,target_iters_v4);

            let sender_thread = thread::spawn(move || {

                init_var!(u64; 0; send_success, send_failed, blocked);
                for (index, assigned_range) in assigned_ranges.into_iter().enumerate() {
                    if assigned_range.2 != 0 {
                        // 如果目标范围 数量不为 0

                        prepare_data!(; clone; probe_v4, base_conf, sender_conf);
                        // 使用 目标范围起始位置 进一步优化约束范围
                        let blocker_v4 = blocker_v4.gen_local_constraints(v4_ranges[index].0, v4_ranges[index].1);
                        let tar_iter_v4 = target_iters_v4[index].init(assigned_range.0, assigned_range.1);

                        let res = send_v4_port(0, tar_iter_v4, 0,        // 局部目标数量设为0, 使速率控制器以全局速率发送
                                            blocker_v4,probe_v4, ttl, base_conf, sender_conf);

                        send_success += res.0; send_failed += res.1; blocked += res.2;
                    }
                }
                (send_success, send_failed, blocked)
            });
            sender_threads.push(sender_thread);
        }

        // 执行 ipv6 发送线程
        for assigned_ranges in self.assigned_target_range_v6.iter() {

            prepare_data!(self; ttl);
            prepare_data!(;clone;assigned_ranges);
            prepare_data!(self; clone; target_iters_v6, base_conf, sender_conf, probe_v6, blocker_v6, v6_ranges);

            let sender_thread = thread::spawn(move || {

                init_var!(u64; 0; send_success, send_failed, blocked);
                for (index, assigned_range) in assigned_ranges.into_iter().enumerate() {
                    if assigned_range.2 != 0 {
                        // 如果目标范围 数量不为 0

                        prepare_data!(; clone; probe_v6, base_conf, sender_conf);
                        let blocker_v6 = blocker_v6.gen_local_constraints(v6_ranges[index].0, v6_ranges[index].1);
                        let tar_iter_v6 = target_iters_v6[index].init(assigned_range.0, assigned_range.1);

                        let res = send_v6_port(0, tar_iter_v6, 0,
                                                      blocker_v6,probe_v6, ttl, base_conf, sender_conf);

                        send_success += res.0; send_failed += res.1; blocked += res.2;
                    }
                }
                (send_success, send_failed, blocked)
            });
            sender_threads.push(sender_thread);
        }

        // 等待发送线程执行完成, 并收集汇总从各个发送线程传递回来的信息
        init_var!(u64; 0; total_send_success,  total_send_failed, total_blocked);
        wait_sender_threads!(sender_threads; send_success, send_failed, blocked; {
            total_send_success += send_success;
            total_send_failed += send_failed;
            total_blocked += blocked;
        });

        println!("{} {} {} {}", SYS.get_info("print", "send_finished"), total_send_success, total_send_failed, total_blocked);

        // 计算终止时间 并向接收线程传递
        ending_the_receiving_thread!(self; recv_close_time_sender);

        // 等待接收线程按照预定时间关闭
        if let Ok((receiver_info_v4, receiver_info_v6)) = receiver_res.join() {
            // 处理接收线程返回的信息

            // 记录结束发送的时间
            computing_time!(start_time; end_time, running_time);

            println!("{} {} {} {} {} {} {}", SYS.get_info("print", "recv_finished_mix"),
                     receiver_info_v4.recv_success, receiver_info_v4.recv_repeat, receiver_info_v4.recv_failed,
                     receiver_info_v6.recv_success, receiver_info_v6.recv_repeat, receiver_info_v6.recv_failed);

            write_to_summary!(self; "CycleV4V6"; "result";
                [start_time, end_time, running_time, total_send_success, total_send_failed, total_blocked;];
                #[receiver_info_v4;; ("recv_success_v4", recv_success), ("recv_failed_v4", recv_failed), ("recv_repeat_v4", recv_repeat), ("recv_validation_passed_v4", recv_validation_passed), ("recv_validation_failed_v4", recv_validation_failed)];
                #[receiver_info_v6;; ("recv_success_v6", recv_success), ("recv_failed_v6", recv_failed), ("recv_repeat_v6", recv_repeat), ("recv_validation_passed_v6", recv_validation_passed), ("recv_validation_failed_v6", recv_validation_failed)]
            );
        } else {  error!("{}", SYS.get_info("err", "recv_thread_err")); exit(1) }
    }
}