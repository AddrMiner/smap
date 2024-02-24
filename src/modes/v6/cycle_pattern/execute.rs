use std::process::exit;
use std::thread;
use chrono::{Local};
use log::error;
use crate::core::receiver::pcap::PcapReceiver;
use crate::core::sender::{send_v6, send_v6_port};
use crate::modes::ModeMethod;
use crate::modes::v6::cycle_pattern::CycleV6Pattern;
use crate::modules::target_iterators::CycleIpv6PatternType;
use crate::{computing_time, creat_channels, ending_the_receiving_thread, init_var, prepare_data, recv_ready, SYS, wait_sender_threads, write_to_summary};
use crate::tools::check_duplicates::bit_map::{BitMapV6Pattern, BitMapV6PatternPort};

impl ModeMethod for CycleV6Pattern {

    /// zmap_v6_pattern 执行函数
    fn execute(&self){

        // 创建信息传递管道
        creat_channels!((recv_ready_sender, recv_ready_receiver, bool),(recv_close_time_sender, recv_close_time_receiver, i64));

        // 执行接收线程
        let receiver_res;
        {
            prepare_data!(self; ip_bits_num, base_ip_val, mask);
            prepare_data!(self; clone; parts, base_conf, receiver_conf, probe);

            match &self.target_iter {
                CycleIpv6PatternType::CycleIpv6Pattern(_) => {
                    receiver_res = thread::spawn(move || {
                        let bit_map = BitMapV6Pattern::new(ip_bits_num, base_ip_val, mask, parts);
                        PcapReceiver::run_v6(0, base_conf, receiver_conf, probe, bit_map,
                                                     recv_ready_sender, recv_close_time_receiver)
                    });
                }
                CycleIpv6PatternType::CycleIpv6PatternPort(t) => {
                    let sports = self.sender_conf.source_ports.clone();
                    let tar_ports = t.tar_ports.clone();

                    receiver_res = thread::spawn(move || {
                        let bit_map = BitMapV6PatternPort::new(ip_bits_num, base_ip_val, mask, parts, tar_ports);
                        PcapReceiver::run_v6_port(0, base_conf, receiver_conf, probe, sports, bit_map,
                                                          recv_ready_sender, recv_close_time_receiver)
                    });
                }
            }
        }

        // 只有接收线程准备完毕后，发送线程才能继续执行
        recv_ready!(recv_ready_receiver);

        // 记录 开始发送的时间
        let start_time = Local::now();

        // 执行发送线程
        let mut sender_threads = vec![];
        for assigned_targets in self.assigned_target_range.iter() {

            prepare_data!(self; ttl);
            prepare_data!(self; clone; blocker, base_conf, sender_conf, probe);

            let sender_thread;
            match &self.target_iter {
                CycleIpv6PatternType::CycleIpv6Pattern(t) => {
                    // 初始化 局部目标迭代器
                    let target_iter = t.init(assigned_targets.0, assigned_targets.1);
                    sender_thread = thread::spawn(move || {
                        send_v6(0, target_iter, 0, blocker, probe, ttl, base_conf, sender_conf)
                    });
                }
                CycleIpv6PatternType::CycleIpv6PatternPort(t) => {
                    let target_iter = t.init(assigned_targets.0, assigned_targets.1);
                    sender_thread = thread::spawn(move || {
                        send_v6_port(0, target_iter, 0, blocker, probe, ttl, base_conf, sender_conf)
                    });
                }
            }
            sender_threads.push(sender_thread);
        }

        // 等待发送线程执行完成, 并收集汇总从各个发送线程传递回来的信息
        init_var!(u64; 0; total_send_success, total_send_failed, total_blocked);
        wait_sender_threads!(sender_threads; send_success, send_failed, blocked; {
            total_send_success += send_success;
            total_send_failed += send_failed;
            total_blocked += blocked;
        });
        println!("{} {} {} {}", SYS.get_info("print", "send_finished"), total_send_success, total_send_failed, total_blocked);

        // 计算终止时间 并向接收线程传递
        ending_the_receiving_thread!(self; recv_close_time_sender);

        // 等待接收线程按照预定时间关闭
        if let Ok(receiver_info) = receiver_res.join() {
            // 处理接收线程返回的信息

            // 计算 结束时间 和 格式化后的运行时间 并显示
            computing_time!(start_time; end_time, running_time);
            println!("{} {} {} {}", SYS.get_info("print", "recv_finished_with_out_of_range"), receiver_info.recv_success, receiver_info.recv_repeat, receiver_info.recv_failed);

            write_to_summary!(self; "CycleV6Pattern"; "result";
                [start_time, end_time, running_time, total_send_success, total_send_failed, total_blocked;];
                #[receiver_info; recv_success, recv_failed, recv_validation_passed, recv_validation_failed; ("receive_repeat_and_out_of_range", recv_repeat)]
            );
        } else { error!("{}", SYS.get_info("err", "recv_thread_err")); exit(1) }
    }
}