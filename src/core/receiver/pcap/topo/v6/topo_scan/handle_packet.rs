
use crate::core::receiver::pcap::PcapReceiver;
use crate::modules::output_modules::OutputMethod;
use crate::modules::probe_modules::topology_probe::topo_mod_v6::TopoMethodV6;
use crate::modules::target_iterators::TopoStateChainV6;
use crate::tools::encryption_algorithm::aes::AesRand;

impl PcapReceiver {


    pub fn topo_scan_handle_packet_v6(ts:&libc::timeval, net_layer_header_and_data:&[u8], state_chain:&mut TopoStateChainV6,
                                      aes_rand:&AesRand, probe:&Box<dyn TopoMethodV6>, output:&mut Box<dyn OutputMethod>){

        // ipv6数据包(包括数据)的长度必须大于 40
        if 40 > net_layer_header_and_data.len() { return }

        // 网络层数据
        let net_layer_data = &net_layer_header_and_data[40..];

        match probe.parse_packet_v6(ts, net_layer_header_and_data, net_layer_data, aes_rand){
            Some(res) => {
                // 拓扑扫描 接收线程处理逻辑

                // 获取 目标ip 索引
                let ip_index = state_chain.get_ip_index(res.dest_ip) as usize;

                if (state_chain.state_chain[ip_index] >> 1) == res.distance {
                    // 注意: 只有 目标地址 的距离 与 发送时设定的 ttl一致时才是有效的, 此处务必谨慎检查

                    // 输出该条目信息
                    output.writer_line(&probe.print_record(&res, net_layer_header_and_data));

                    let responder = res.responder;

                    if !state_chain.hash_set.contains(&responder) {
                        // 如果 当前响应ip 未被标记

                        // 需要 对当前 目标ip, 继续向后探测, 下一ttl 应该被设为 当前ttl减一
                        // 注意 最后一位 被标记为1
                        state_chain.set_next_ttl_state(ip_index, res.distance - 1);

                        // 在 哈希表 中 对该响应ip 进行标记
                        state_chain.hash_set.insert(responder);
                    } else {
                        // 如果 当前响应ip 已经被标记

                        // case1: 当前发送轮次的重复响应(注意:在这种情况下, 状态链中的ttl已经减一)
                        // case2: 遇到了 前向分岔点, 需要 对当前 目的ip 置0(停止在该ip上继续探测)


                        // 永远终止 对 该目标ip 的探测
                        state_chain.close_cur_tar_ip(ip_index);

                    }
                }
            }
            None => return,
        }
    }



}