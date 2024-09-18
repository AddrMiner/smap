use std::net::Ipv6Addr;
use std::sync::Arc;
use log::debug;
use crate::SYS;
use crate::core::conf::set_conf::base_conf::BaseConf;
use crate::core::conf::set_conf::sender_conf::SenderBaseConf;
use crate::core::sender::tools::rate_controller::RateController;
use crate::core::sender::tools::source_ip_iter::source_ip_v6::SourceIpIterV6;
use crate::modules::probe_modules::probe_mod_v6::ProbeModV6;
use crate::modules::target_iterators::{PmapFileIterV6, PmapGraph};


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
pub fn pmap_file_recommend_scan_send_v6_port(
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

    // 初始化 PID速率控制器                                                                          强制全局指导速率
    let mut rate_controller = RateController::from_conf(&sender_conf.global_rate_conf, 0, batch_size as f64);

    drop(base_conf);
    drop(sender_conf);

    // 取出地址迭代器
    let ip_iter = target_iter.tar_ips.iter();

    let mut batch_count:u64 = 0;
    let graph_ptr = &graph;

    // 每次取出一个地址 及其 对应的ip结构体
    for (ip, ip_struct) in ip_iter.zip(target_iter.ips_struct.iter_mut()) {

        // 由pmap生成推荐端口
        let cur_port = ip_struct.send_port(graph_ptr);

        let cur_source_ip = source_ip_iter.get_src_ip_with_change();

        // 由探测模块生成数据包
        let packet = probe.make_packet_v6(cur_source_ip, *ip, cur_port, None, &aes_rand);

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
            debug!("{} {} {}", SYS.get_info("debug", "send_failed"), Ipv6Addr::from(*ip), cur_port);
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

    (send_success, send_failed, target_iter)
}