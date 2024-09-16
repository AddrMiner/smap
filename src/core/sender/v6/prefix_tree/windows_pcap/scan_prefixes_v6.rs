use std::sync::Arc;
use log::debug;
use crate::core::conf::set_conf::base_conf::BaseConf;
use crate::core::conf::set_conf::sender_conf::SenderBaseConf;
use crate::core::sender::tools::rate_controller::RateController;
use crate::core::sender::tools::source_ip_iter::source_ip_v6::SourceIpIterV6;
use crate::core::sys::packet_sender::PcapSender;
use crate::modules::probe_modules::topology_probe::topo_mod_v6::TopoModV6;
use crate::SYS;

pub fn send_prefixes_v6(
    interface_index:usize, targets:Vec<(u128, u8, u8)>,
    probe_mod_v6: Arc<TopoModV6>, base_conf:Arc<BaseConf>, sender_conf:Arc<SenderBaseConf>
) -> (u64, u64) {

    // 初始化 pcap 发包器
    let (mut pcap_sender, mut send_queue, batch_size) = PcapSender::init(
        &base_conf.interface[interface_index].name_index.0, sender_conf.global_rate_conf.batch_size,
        probe_mod_v6.max_packet_length_v6);

    // 取出常用变量
    let send_attempts = sender_conf.send_attempt_num;
    let send_attempts_sub_one = sender_conf.send_attempt_num - 1;
    
    let mut total_send_success:u64 = 0;
    let mut total_send_failed:u64 = 0;

    // 初始化 源地址迭代器
    let source_ip_iter = SourceIpIterV6::new(&sender_conf.source_addrs_v6[interface_index]);
    let cur_source_ip = source_ip_iter.get_src_ip();
    drop(source_ip_iter);

    // 初始化 拓扑探测模块
    let mut probe = TopoModV6::init(probe_mod_v6, sender_conf.source_ports.clone());

    // 探测模块线程初始化
    probe.thread_initialize_v6(&base_conf.interface[interface_index].local_mac,
                               &base_conf.interface[interface_index].gateway_mac);

    let aes_rand = base_conf.aes_rand.clone();

    // 初始化 PID速率控制器
    let mut rate_controller = RateController::from_conf(&sender_conf.global_rate_conf, 0, batch_size as f64);
    
    drop(base_conf);
    drop(sender_conf);

    let mut batch_count = 0u32;
    let mut batch_send_success: u64 = 0;
    let mut batch_send_failed: u64 = 0;
    
    for (tar_addr, tar_ttl, code) in targets.into_iter() {

        // 由探测模块生成数据包
        let packet = probe.make_packet_v6(cur_source_ip, tar_addr, None, code, tar_ttl, &aes_rand);

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

        batch_count += 1;
        if batch_count >= batch_size {
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

            batch_count = 0;
            batch_send_success = 0;
            batch_send_failed = 0;
        }
    }
    (total_send_success, total_send_failed)
}