use std::net;
use std::sync::Arc;
use log::debug;
use crate::SYS;
use crate::core::conf::set_conf::base_conf::BaseConf;
use crate::core::conf::set_conf::sender_conf::SenderBaseConf;
use crate::core::sender::tools::rate_controller::RateController;
use crate::core::sender::tools::source_ip_iter::source_ip_v6::SourceIpIterV6;
use crate::modules::probe_modules::probe_mod_v6::ProbeModV6;
use crate::modules::target_iterators::{PmapFileIterV6, PmapGraph, PmapIpStruct};
use net::Ipv6Addr;

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
pub fn pmap_file_recommend_new_scan_send_v6_port(
    interface_index:usize, mut target_iter:PmapFileIterV6, probe_mod_v6: Arc<ProbeModV6>,
    graph:Arc<PmapGraph>, base_conf:Arc<BaseConf>, sender_conf:Arc<SenderBaseConf>
) -> (u64, u64, PmapFileIterV6) {

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

    // 初始化 探测模块
    let mut probe = ProbeModV6::init(probe_mod_v6, sender_conf.source_ports.clone());

    // 探测模块线程初始化
    probe.thread_initialize_v6(&base_conf.interface[interface_index].local_mac,
                               &base_conf.interface[interface_index].gateway_mac);

    let aes_rand = base_conf.aes_rand.clone();

    // 注意: 同一网络内所有地址的初始状态和初始推荐端口都一致
    let mut first_ip_struct = PmapIpStruct::new();
    let first_port = first_ip_struct.send_port(&graph);
    let first_ip_struct = first_ip_struct;

    // 初始化 PID速率控制器                                                                          强制全局指导速率
    let mut rate_controller = RateController::from_conf(&sender_conf.global_rate_conf, 0, batch_size as f64);

    drop(base_conf);
    drop(sender_conf);

    // 取出地址迭代器
    let ip_iter = target_iter.tar_ips.iter();
    
    let mut batch_count:u64 = 0;
    // 每次取出一个地址
    for ip in ip_iter {

        let cur_source_ip = source_ip_iter.get_src_ip_with_change();

        // 注意: 由于在同一网络内第一个推荐端口一致, 这里直接复制
        // 警告: 请注意 ips_struct 的添加顺序和总数 与 有效ip 保持一致
        target_iter.ips_struct.push(first_ip_struct.clone());

        // 由探测模块生成数据包
        let packet = probe.make_packet_v6(
            cur_source_ip, *ip, first_port, None, &aes_rand);

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
            debug!("{} {} {}", SYS.get_info("debug", "send_failed"), Ipv6Addr::from(*ip), first_port);
            send_failed += 1;
        }

        batch_count += 1;
        if batch_count % batch_size == 0 {
            // 当 发送的数量 达到一个批次数量
            
            // 批次内计数重置
            batch_count = 0;

            // 批次速率控制
            rate_controller.sleep();
        }
    }

    // 将 保存所有地址状态信息的向量 中的 冗余容量 进行清除
    target_iter.ips_struct.shrink_to_fit();

    (send_success, send_failed, target_iter)
}
