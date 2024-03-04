use crate::core::receiver::pcap::PcapReceiver;
use crate::modules::output_modules::OutputMethod;
use crate::modules::probe_modules::topology_probe::topo_mod_v4::TopoMethodV4;
use crate::modules::target_iterators::TopoStateChainV4;
use crate::tools::encryption_algorithm::aes::AesRand;

impl PcapReceiver {


    pub fn topo_sub_pre_scan_handle_packet_v4(ts:&libc::timeval, net_layer_header_and_data:&[u8], active_count:&mut u32,
                                          state_chain:&mut TopoStateChainV4, aes_rand:&AesRand,
                                          probe:&Box<dyn TopoMethodV4>, output:&mut Box<dyn OutputMethod>){

        let ipv4_header_len = ((net_layer_header_and_data[0] & 0b_0000_1111u8) as usize) * 4;

        // ipv4数据包(包括数据)的长度必须大于 首部长度
        if ipv4_header_len > net_layer_header_and_data.len() { return }

        // 网络层数据
        let net_layer_data = &net_layer_header_and_data[ipv4_header_len..];

        match probe.parse_packet_v4(ts, net_layer_header_and_data, net_layer_data, aes_rand){
            Some(res) => {

                if res.from_destination {
                    // 如果是从 目标ip 获得的响应
                    // 预扫描阶段从 目标ip 获得响应，可获得 目标主机的 往返延迟，跳数信息

                    // 注意: 如果 在拓扑探测模块中 允许 从目标网络响应, 目标地址可能与响应地址不同

                    let responder = res.responder;
                    let responder_usize = responder as usize;

                    if state_chain.not_marked(responder_usize) {
                        // 如果 该响应地址 未被标记

                        if state_chain.in_range(responder) {
                            // 如果 响应来自 目标地址范围, 标记 响应ip

                            *active_count += 1;

                            // 输出该条目信息
                            output.writer_line(&probe.print_record(&res, net_layer_header_and_data));

                            // 获取目标索引
                            let ip_index = state_chain.get_ip_index(responder);

                            // 标记该 目标ip, 注意 预扫描 时不设置 接收状态
                            state_chain.set_next_ttl(ip_index as usize, res.distance-1);

                            // 在位图中 对该响应ip 进行标记
                            state_chain.bit_map.set(responder_usize, true);
                        } else {
                            // 如果 响应不来自 目标地址范围
                            // 比如, 从同一网络中其他ip回复的 主机不可达消息
                            
                            // 检查 该响应的目的ip 是否已经存在状态
                            // 获取目标索引
                            let ip_index = state_chain.get_ip_index(res.dest_ip) as usize;
                            
                            if state_chain.state_chain[ip_index] == 0 {
                                // 如果 对应的目的ip 不存在状态
                                // 一般来说, 预扫描辅助扫描的准确度不如预扫描(一般为icmp正向推断)

                                *active_count += 1;

                                // 输出该条目信息
                                output.writer_line(&probe.print_record(&res, net_layer_header_and_data));

                                // 标记该 目标ip, 注意 预扫描 时不设置 接收状态
                                state_chain.set_next_ttl(ip_index, res.distance-1);

                                // 在位图中 对该响应ip 进行标记
                                state_chain.bit_map.set(responder_usize, true);
                            }
                        }
                    }
                }
            }
            None => return,
        }
    }
}