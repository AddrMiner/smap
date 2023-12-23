use std::sync::Arc;
use log::debug;
use crate::SYS;
use crate::core::conf::set_conf::base_conf::BaseConf;
use crate::core::conf::set_conf::sender_conf::SenderBaseConf;
use crate::core::sender::tools::rate_controller::RateController;
use crate::core::sender::tools::source_ip_iter::source_ip_v6::SourceIpIterV6;
use crate::core::sys::packet_sender::PcapSender;
use crate::modules::probe_modules::probe_mod_v6::ProbeModV6;
use crate::modules::target_iterators::{Ipv6Iter};
use crate::tools::blocker::ipv6_blocker::BlackWhiteListV6;


pub fn send_v6<T:Ipv6Iter>(interface_index:usize, mut target_iter:T, local_tar_num:u64,
                           blocker:BlackWhiteListV6, probe_mod_v6: Arc<ProbeModV6>, hop_limit:Option<u8>,
                           base_conf:Arc<BaseConf>, sender_conf:Arc<SenderBaseConf>) -> (u64, u64, u64) {

    // 初始化 pcap 发包器
    let (mut pcap_sender, mut send_queue, batch_size) = PcapSender::init(
        &base_conf.interface[interface_index].name_index.0, sender_conf.global_rate_conf.batch_size,
        probe_mod_v6.max_packet_length_v6);

    // 取出常用变量
    let send_attempts = sender_conf.send_attempt_num;
    let send_attempts_sub_one = send_attempts - 1;

    // 统计当前线程的 发送成功数量 和 发送失败数量
    // 同一 ip port 对, 成功 或 失败 发送算一次
    let mut total_send_success:u64 = 0;
    let mut total_send_failed:u64 = 0;
    let mut total_blocked:u64 = 0;

    // 初始化 源地址迭代器
    let mut source_ip_iter = SourceIpIterV6::new(&sender_conf.source_addrs_v6[interface_index]);

    // 初始化 探测模块
    let mut probe = ProbeModV6::init(probe_mod_v6, sender_conf.source_ports.clone());

    // 探测模块线程初始化
    // 建议: 由 探测模块 生成 原始数据包缓冲区, 包含所有数据包中不变的内容, 后续改动直接在此基础上修改
    probe.thread_initialize_v6(&base_conf.interface[interface_index].local_mac,
                               &base_conf.interface[interface_index].gateway_mac);

    let aes_rand = base_conf.aes_rand.clone();

    // 获得首个目标     0:是否为非最终值, 1:最终值是否有效, 2:ip地址
    let mut cur_target = target_iter.get_first_ip();

    // 初始化 PID速率控制器
    let mut rate_controller = RateController::from_conf(&sender_conf.global_rate_conf, local_tar_num, batch_size as f64);

    drop(base_conf);
    drop(sender_conf);

    'big_batch:loop {

        let mut batch_send_success:u64 = 0;
        let mut batch_send_failed:u64 = 0;

        for _ in 0..batch_size {

            if cur_target.0 {
                // 如果不是最终值

                if blocker.ip_is_avail(cur_target.2) {
                    // 如果没被黑名单阻止

                    let cur_source_ip = source_ip_iter.get_src_ip_with_change();

                    // 由探测模块生成数据包
                    let packet = probe.make_packet_v6(
                        cur_source_ip, cur_target.2, 0, hop_limit, &aes_rand);

                    let mut add_successfully = false;
                    for _ in 0..send_attempts {
                        // 使用pcap尝试将数据包添加到 发送队列
                        match send_queue.queue(None, &packet) {
                            Ok(_) => {
                                // 如果成功就跳出
                                add_successfully = true;
                                break
                            }
                            Err(_) => {}
                        }
                    }
                    if add_successfully {
                        batch_send_success += 1;
                    } else {
                        batch_send_failed += 1;
                    }
                } else {
                    total_blocked += 1;
                }

                // 获取下一个目标
                cur_target = target_iter.get_next_ip();
            } else {
                // 如果是最终值

                if cur_target.1 {
                    // 最终值有效

                    if blocker.ip_is_avail(cur_target.2) {
                        // 如果当前 ip 被放行

                        let cur_source_ip = source_ip_iter.get_src_ip_with_change();

                        // 由探测模块生成数据包
                        let packet = probe.make_packet_v6(
                            cur_source_ip, cur_target.2, 0, hop_limit, &aes_rand);

                        let mut add_successfully = false;
                        for _ in 0..send_attempts {
                            // 使用pcap尝试将数据包添加到 发送队列
                            match send_queue.queue(None,&packet) {
                                Ok(_) => {
                                    // 如果成功就跳出
                                    add_successfully = true;
                                    break
                                }
                                Err(_) => {}
                            }
                        }
                        if add_successfully {
                            batch_send_success += 1;
                        } else {
                            batch_send_failed += 1;
                        }
                    } else {
                        total_blocked += 1;
                    }

                }


                for a in 0..send_attempts {
                    match send_queue.transmit(&mut pcap_sender, pcap::sendqueue::SendSync::Off) {
                        Ok(_) => {
                            // 警告: 如果整个队列都被成功发送, 成功的数量按照 成功进入队列的数据包进行计算, 失败的数量按照 添加队列失败的进行计算
                            total_send_success += batch_send_success;
                            total_send_failed += batch_send_failed;
                            break;
                        }
                        Err(_) => {

                            if a == send_attempts_sub_one {
                                // 如果是最后一次尝试
                                // 失败数量是 成功添加 和 添加失败的数量相加
                                total_send_failed = total_send_failed + batch_send_success + batch_send_failed;
                                debug!("{} {}", SYS.get_info("debug", "send_queue_failed"), total_send_failed);
                            }
                        }
                    }
                }

                // 处理完最终值, 直接退出大循环
                break 'big_batch;
            }
        }

        for a in 0..send_attempts {
            match send_queue.transmit(&mut pcap_sender, pcap::sendqueue::SendSync::Off) {
                Ok(_) => {
                    // 警告: 如果整个队列都被成功发送, 成功的数量按照 成功进入队列的数据包进行计算, 失败的数量按照 添加队列失败的进行计算
                    total_send_success += batch_send_success;
                    total_send_failed += batch_send_failed;
                    break;
                }
                Err(_) => {

                    if a == send_attempts_sub_one {
                        // 如果是最后一次尝试
                        // 失败数量是 成功添加 和 添加失败的数量相加
                        total_send_failed = total_send_failed + batch_send_success + batch_send_failed;
                        debug!("{} {}", SYS.get_info("debug", "send_queue_failed"), total_send_failed);
                    }
                }
            }
        }

        rate_controller.sleep();
    }

    (total_send_success, total_send_failed, total_blocked)
}

