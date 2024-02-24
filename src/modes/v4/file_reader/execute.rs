use std::process::exit;
use std::thread;
use chrono::{Local};
use log::error;
use crate::core::receiver::pcap::PcapReceiver;
use crate::core::sender::{send_file_v4_port};
use crate::modes::ModeMethod;
use crate::modes::v4::file_reader::V4FileReader;
use crate::{computing_time, creat_channels, ending_the_receiving_thread, init_var, prepare_data, recv_ready, SYS, wait_sender_threads, write_to_summary};
use crate::tools::check_duplicates::hash_set::HashSetV4Port;

impl ModeMethod for V4FileReader {

    fn execute(&self){

        // 创建信息传递管道
        creat_channels!((recv_ready_sender, recv_ready_receiver, bool),(recv_close_time_sender, recv_close_time_receiver, i64));

        // 执行接收线程
        let receiver_res;
        {
            prepare_data!(self; clone; base_conf, receiver_conf, probe);
            let sports = self.sender_conf.source_ports.clone();
            let tar_num = self.tar_num.map_or(256, |v| {v as usize});

            receiver_res = thread::spawn(move || {
                // PcapReceiver::run_v4_port_hash(0, base_conf, receiver_conf, probe, tar_num,  sports,
                //                      recv_ready_sender, recv_close_time_receiver)
                // 初始化 哈希集合查重器
                let hash_set = HashSetV4Port::new(tar_num);
                PcapReceiver::run_v4_port(0, base_conf, receiver_conf, probe, sports, hash_set, recv_ready_sender, recv_close_time_receiver)
            });
        }

        // 只有接收线程准备完毕后，发送线程才能继续执行
        recv_ready!(recv_ready_receiver);

        // 记录 开始发送的时间
        let start_time = Local::now();

        // 执行发送线程
        init_var!(u64; 0; total_send_success, total_send_failed, total_blocked);
        for tar_port in self.tar_ports.iter() {

            let mut sender_threads = vec![];
            for assigned_targets in self.assigned_target_range.iter() {

                // 初始化 局部目标迭代器
                let target_iter_option = self.target_iter.get_ipv4_file_reader(assigned_targets, *tar_port);

                if let Some(target_iter) = target_iter_option {
                    // 获得有效目标迭代器

                    prepare_data!(self; ttl);
                    prepare_data!(self; clone; blocker, base_conf, sender_conf, probe);

                    let sender_thread = thread::spawn(move || {
                        send_file_v4_port(0, target_iter, 0, blocker, probe, ttl, base_conf, sender_conf)
                    });
                    sender_threads.push(sender_thread);
                }
            }

            wait_sender_threads!(sender_threads; send_success, send_failed, blocked; {
                total_send_success += send_success;
                total_send_failed += send_failed;
                total_blocked += blocked;
            });
        }

        println!("{} {} {} {}", SYS.get_info("print", "send_finished"), total_send_success, total_send_failed, total_blocked);

        // 计算终止时间 并向接收线程传递
        ending_the_receiving_thread!(self; recv_close_time_sender);

        // 等待接收线程按照预定时间关闭
        if let Ok(receiver_info) = receiver_res.join() {
            // 处理接收线程返回的信息

            // 计算 结束时间 和 格式化后的运行时间 并显示
            computing_time!(start_time; end_time, running_time);
            println!("{} {} {} {}", SYS.get_info("print", "recv_finished"), receiver_info.recv_success, receiver_info.recv_repeat, receiver_info.recv_failed);

            write_to_summary!(self; "V4FileReader"; "result";
                [start_time, end_time, running_time, total_send_success, total_send_failed, total_blocked;];
                #[receiver_info; recv_success, recv_failed, recv_repeat, recv_validation_passed, recv_validation_failed; ]
            );
        } else {  error!("{}", SYS.get_info("err", "recv_thread_err")); exit(1) }
    }
}