use std::process::exit;
use std::sync::mpsc;
use std::thread;
use chrono::{Local, Utc};
use log::error;
use crate::core::receiver::pcap::PcapReceiver;
use crate::core::sender::{send_cycle_group_v6};
use crate::modes::ModeMethod;
use crate::modes::v6::cycle::CycleV6;
use crate::SYS;
use crate::tools::file::write_to_file::write_record;
use crate::tools::others::time::get_fmt_duration;

impl ModeMethod for CycleV6 {

    /// zmap_v6 执行函数
    fn execute(&self){

        // 创建信息传递管道
        let (recv_ready_sender, recv_ready_receiver) = mpsc::channel();
        let (recv_close_time_sender, recv_close_time_receiver) = mpsc::channel();

        // 执行接收线程
        let receiver_res;
        {
            let start_ip = self.start_ip;
            let end_ip = self.end_ip;
            let tar_ip_num = self.tar_ip_num;

            let base_conf = self.base_conf.clone();
            let receiver_conf = self.receiver_conf.clone();
            let probe = self.probe.clone();

            let sports = self.sender_conf.source_ports.clone();
            let tar_ports = self.target_iter.tar_ports.clone();

            receiver_res = thread::spawn(move || {
                PcapReceiver::run_v6(0, base_conf, receiver_conf, probe,
                                     start_ip, end_ip, tar_ip_num, sports, tar_ports,
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

        // 执行发送线程
        let mut sender_threads = vec![];
        for assigned_targets in self.assigned_target_range.iter() {

            // 初始化 局部目标迭代器
            let target_iter = self.target_iter.init(assigned_targets.0, assigned_targets.1);
            let local_tar_num = assigned_targets.2;

            // 为拦截器设置局部限制范围, 这里使用全局配置
            let blocker = self.blocker.clone();
            let base_conf = self.base_conf.clone();
            let sender_conf = self.sender_conf.clone();
            let probe = self.probe.clone();

            let sender_thread = thread::spawn(move || {
                send_cycle_group_v6(0, target_iter, local_tar_num,
                                    blocker,probe, None, base_conf, sender_conf)
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
        if let Ok(receiver_info) = receiver_res.join() {
            // 处理接收线程返回的信息

            // 记录结束发送的时间
            let end_time = Local::now();
            let running_time = (end_time - start_time).num_seconds();
            let running_time = get_fmt_duration(running_time, SYS.get_info("print", "running_time_pattern"));

            println!("{} {} {} {}", SYS.get_info("print", "recv_finished_with_out_of_range"), receiver_info.success_total, receiver_info.repeat_total, receiver_info.failed_total);
            println!("{} {}", SYS.get_info("print", "show_running_time"), running_time);

            if let Some(summary_path) = &self.base_conf.summary_file {
                // 将所有信息写入记录文件

                let header = vec!["start_time", "end_time", "running_time",
                                  "send_success", "send_failed", "send_blocked",

                                  "receive_success", "receive_failed",
                                  "receive_repeat_and_out_of_range", "receive_validation_passed",
                                  "receive_validation_failed"];
                let val = vec![ start_time.to_string(), end_time.to_string(), running_time,
                                total_send_success.to_string(), total_send_failed.to_string(), total_blocked.to_string(),

                                receiver_info.success_total.to_string(), receiver_info.failed_total.to_string(),
                                receiver_info.repeat_total.to_string(), receiver_info.validation_passed.to_string(),
                                receiver_info.validation_failed.to_string()];

                write_record("CycleV6", "result", summary_path, header, val);
            }
        } else {
            error!("{}", SYS.get_info("err", "recv_thread_err"));
            exit(1)
        }
    }
}