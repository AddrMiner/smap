
use std::net::Ipv6Addr;
use std::sync::Arc;
use log::debug;
use crate::SYS;
use crate::core::conf::set_conf::base_conf::BaseConf;
use crate::core::conf::set_conf::sender_conf::SenderBaseConf;
use crate::core::sender::tools::rate_controller::RateController;
use crate::core::sender::tools::source_ip_iter::source_ip_v6::SourceIpIterV6;
use crate::modules::target_iterators::Topo6Iter;
use crate::modules::probe_modules::topology_probe::topo_mod_v6::TopoModV6;

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
pub fn topo_scan_send_v6<T:Topo6Iter>(interface_index:usize, mut target_iter:T, probe_mod_v6: Arc<TopoModV6>,
                                      base_conf:Arc<BaseConf>, sender_conf:Arc<SenderBaseConf>) -> (u64, u64) {

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

    // 初始化 源地址迭代器
    let mut source_ip_iter = SourceIpIterV6::new(&sender_conf.source_addrs_v6[interface_index]);
    let cur_source_ip = source_ip_iter.get_src_ip_with_change();

    // 初始化 拓扑探测模块
    let mut probe = TopoModV6::init(probe_mod_v6, sender_conf.source_ports.clone());

    // 探测模块线程初始化
    probe.thread_initialize_v6(&base_conf.interface[interface_index].local_mac,
                               &base_conf.interface[interface_index].gateway_mac);

    let aes_rand = base_conf.aes_rand.clone();

    // 获得首个目标     0:是否为非最终值, 1:最终值是否有效, 2:ip地址, 3:ttl
    let mut cur_target = target_iter.get_first_ip_ttl();

    // 初始化 PID速率控制器
    let mut rate_controller = RateController::from_conf(&sender_conf.global_rate_conf, 0, batch_size as f64);

    drop(base_conf);
    drop(sender_conf);

    'big_batch:loop {

        for _ in 0..batch_size {

            if cur_target.0 {
                // 如果不是最终值

                // 由探测模块生成数据包
                let packet = probe.make_packet_v6(
                    cur_source_ip, cur_target.2, None, cur_target.3, &aes_rand);

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
                    debug!("{} {} {}", SYS.get_info("debug", "send_failed"), Ipv6Addr::from(cur_target.2), 0);
                    send_failed += 1;
                }

                // 获取下一个目标
                cur_target = target_iter.get_next_ip_ttl();
            } else {
                // 如果是最终值

                if cur_target.1 {
                    // 最终值有效

                    // 由探测模块生成数据包
                    let packet = probe.make_packet_v6(
                        cur_source_ip, cur_target.2, None, cur_target.3, &aes_rand);

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
                        debug!("{} {} {}", SYS.get_info("debug", "send_failed"), Ipv6Addr::from(cur_target.2), 0);
                        send_failed += 1;
                    }
                }
                // 处理完最终值, 直接退出大循环
                break 'big_batch;
            }
        }
        rate_controller.sleep();
    }

    (send_success, send_failed)
}

