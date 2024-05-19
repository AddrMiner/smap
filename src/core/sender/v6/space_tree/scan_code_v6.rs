



use std::net;
use std::sync::Arc;
use log::debug;
use crate::SYS;
use crate::core::conf::set_conf::base_conf::BaseConf;
use crate::core::conf::set_conf::sender_conf::SenderBaseConf;
use crate::core::sender::tools::rate_controller::RateController;
use crate::core::sender::tools::source_ip_iter::source_ip_v6::SourceIpIterV6;
use net::Ipv6Addr;
use crate::modules::probe_modules::active_probe_ipv6_code::CodeProbeModV6;

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
pub fn send_v6_vec(
    interface_index:usize, tar_addrs:Vec<(u16, u128)>,
    probe_mod_v6: Arc<CodeProbeModV6>,
    base_conf:Arc<BaseConf>, sender_conf:Arc<SenderBaseConf>) -> (u64, u64) {


    // 初始化 数据包发送器
    let sender = PacketSender::new(
        &base_conf.interface[interface_index].name_index, &base_conf.interface[interface_index].gateway_mac);

    // 取出常用变量
    let batch_size = sender_conf.global_rate_conf.batch_size;
    let send_attempts = sender_conf.send_attempt_num;

    let mut total_send_success: u64 = 0;
    let mut total_send_failed: u64 = 0;

    // 初始化 源地址迭代器
    let mut source_ip_iter = SourceIpIterV6::new(&sender_conf.source_addrs_v6[interface_index]);

    // 初始化 探测模块
    let mut probe = CodeProbeModV6::init(probe_mod_v6);

    // 探测模块线程初始化
    // 建议: 由 探测模块 生成 原始数据包缓冲区, 包含所有数据包中不变的内容, 后续改动直接在此基础上修改
    probe.thread_initialize_v6(&base_conf.interface[interface_index].local_mac,
                               &base_conf.interface[interface_index].gateway_mac);

    let aes_rand = base_conf.aes_rand.clone();

    // 初始化 PID速率控制器
    let mut rate_controller = RateController::from_conf(&sender_conf.global_rate_conf, 0, batch_size as f64);

    drop(base_conf);
    drop(sender_conf);

    let mut batch_count = 0u64;
    for (region_code, dest_addr) in tar_addrs.into_iter() {
        let cur_source_ip = source_ip_iter.get_src_ip_with_change();

        // 由探测模块生成数据包
        let packet = probe.make_packet_v6(cur_source_ip, dest_addr, region_code.to_be_bytes().into(), &aes_rand);
        
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
            total_send_success += 1;
        } else {
            // 统计发送失败的数据包
            debug!("{} {} {}", SYS.get_info("debug", "send_failed"), Ipv6Addr::from(dest_addr), 0);
            total_send_failed += 1;
        }

        batch_count += 1;
        if batch_count >= batch_size {
            rate_controller.sleep();
            batch_count = 0;
        }
    }

    (total_send_success, total_send_failed)
}

