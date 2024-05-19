
use std::net;
use std::sync::Arc;
use log::debug;
use crate::SYS;
use crate::core::conf::set_conf::base_conf::BaseConf;
use crate::core::conf::set_conf::sender_conf::SenderBaseConf;
use crate::core::sender::tools::rate_controller::RateController;
use crate::core::sender::tools::source_ip_iter::source_ip_v4::SourceIpIterV4;
use crate::modules::probe_modules::probe_mod_v4::ProbeModV4;
use crate::modules::target_iterators::{Ipv4Iter, PmapGraph, PmapIpStruct, PmapIterV4};
use crate::tools::blocker::ipv4_blocker::BlackWhiteListV4;
use net::Ipv4Addr;

#[cfg(any(
target_os = "freebsd",
target_os = "netbsd",
target_os = "illumos",
target_os = "solaris",
target_os = "openbsd",
target_os = "macos",
target_os = "ios",
target_os = "linux"))]
use crate::core::sys::packet_sender::PacketSender;


#[cfg(any(
target_os = "freebsd",
target_os = "netbsd",
target_os = "illumos",
target_os = "solaris",
target_os = "openbsd",
target_os = "macos",
target_os = "ios",
target_os = "linux"))]
pub fn pmap_recommend_new_scan_send_v4_port(interface_index:usize, mut target_iter:PmapIterV4,
                                            blocker:BlackWhiteListV4, probe_mod_v4: Arc<ProbeModV4>, graph:Arc<PmapGraph>,
                                            base_conf:Arc<BaseConf>, sender_conf:Arc<SenderBaseConf>) -> (u64, u64, u64, PmapIterV4) {

    // 初始化 数据包发送器
    let sender = PacketSender::new(
        &base_conf.interface[interface_index].name_index, &base_conf.interface[interface_index].gateway_mac);

    // 取出常用变量
    let batch_size = sender_conf.global_rate_conf.batch_size;
    let send_attempts = sender_conf.send_attempt_num;

    // 统计当前线程的 发送成功数量 和 发送失败数量
    // 同一 ip port 对, 成功 或 失败 发送算一次
    let mut send_success:u64 = 0;
    let mut send_failed:u64 = 0;
    let mut total_blocked:u64 = 0;

    // 初始化 源地址迭代器
    let mut source_ip_iter = SourceIpIterV4::new(&sender_conf.source_addrs_v4[interface_index]);

    // 初始化 探测模块
    let mut probe = ProbeModV4::init(probe_mod_v4, sender_conf.source_ports.clone());

    // 探测模块线程初始化
    probe.thread_initialize_v4(&base_conf.interface[interface_index].local_mac,
                               &base_conf.interface[interface_index].gateway_mac, base_conf.aes_rand.rand_u16);

    let aes_rand = base_conf.aes_rand.clone();

    // 获得首个目标     0:是否为非最终值, 1:最终值是否有效, 2:ip地址
    let mut cur_target = target_iter.ipv4_guide_iter.get_first_ip();

    // 注意: 同一网络内所有地址的初始状态和初始推荐端口都一致
    let mut first_ip_struct = PmapIpStruct::new();
    let first_port = first_ip_struct.send_port(&graph);
    let first_ip_struct = first_ip_struct;

    // 初始化 PID速率控制器         tar_num设为0, 强制使用 全局指导速率
    let mut rate_controller = RateController::from_conf(&sender_conf.global_rate_conf, 0, batch_size as f64);

    drop(base_conf);
    drop(sender_conf);

    'big_batch:loop {

        for _ in 0..batch_size {

            if cur_target.0 {
                // 如果不是最终值

                if blocker.ip_is_avail(cur_target.2) {
                    // 如果没被黑名单阻止

                    // 注意: 由于在同一网络内第一个推荐端口一致, 这里直接复制
                    // 警告: 请注意 ips_struct 的添加顺序和总数 与 有效ip 保持一致
                    target_iter.ips_struct.push(first_ip_struct.clone());
                    let cur_source_ip = source_ip_iter.get_src_ip_with_change();

                    // 由探测模块生成数据包
                    let packet = probe.make_packet_v4(
                        cur_source_ip, cur_target.2, first_port, None, &aes_rand);

                    let mut sent_successfully = false;
                    for _ in 0..send_attempts {
                        let res = sender.send_packet(&packet);

                        if res >= 0 {
                            sent_successfully = true;
                            break;
                        }
                    }
                    if sent_successfully {
                        // 统计发送成功的数据包
                        send_success += 1;
                    } else {
                        // 统计发送失败的数据包
                        debug!("{} {} {}", SYS.get_info("debug", "send_failed"), Ipv4Addr::from(cur_target.2), first_port);
                        send_failed += 1;
                    }
                } else {
                    total_blocked += 1;
                }

                // 获取下一个目标
                cur_target = target_iter.ipv4_guide_iter.get_next_ip();
            } else {
                // 如果是最终值

                if cur_target.1 {
                    // 最终值有效

                    if blocker.ip_is_avail(cur_target.2) {
                        // 如果当前 ip 被放行

                        // 注意: 由于在同一网络内第一个推荐端口一致, 这里直接复制
                        target_iter.ips_struct.push(first_ip_struct.clone());
                        let cur_source_ip = source_ip_iter.get_src_ip_with_change();

                        // 由探测模块生成数据包
                        let packet = probe.make_packet_v4(
                            cur_source_ip, cur_target.2, first_port, None, &aes_rand);

                        let mut sent_successfully = false;
                        for _ in 0..send_attempts {
                            let res = sender.send_packet(&packet);

                            if res >= 0 {
                                sent_successfully = true;
                                break;
                            }
                        }
                        if sent_successfully {
                            // 统计发送成功的数据包
                            send_success += 1;
                        } else {
                            // 统计发送失败的数据包
                            debug!("{} {} {}", SYS.get_info("debug", "send_failed"), Ipv4Addr::from(cur_target.2), first_port);
                            send_failed += 1;
                        }
                    } else {
                        total_blocked += 1;
                    }

                }
                // 处理完最终值, 直接退出大循环
                break 'big_batch;
            }
        }
        rate_controller.sleep();
    }

    // 将 保存所有地址状态信息的向量 中的 冗余容量 进行清除
    target_iter.ips_struct.shrink_to_fit();

    // 重置引导迭代器
    target_iter.reset_guide_iter();

    (send_success, send_failed, total_blocked, target_iter)
}


