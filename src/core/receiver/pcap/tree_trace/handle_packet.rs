use ahash::AHashSet;
use crate::core::receiver::pcap::PcapReceiver;
use crate::modules::output_modules::OutputMethod;
use crate::modules::probe_modules::topo_mod_v6::CodeTopoProbeMethodV6;
use crate::tools::encryption_algorithm::aes::AesRand;

impl PcapReceiver {


    pub fn code_topo_prefix_scan_handle_packet_v6(ts:&libc::timeval, net_layer_header_and_data:&[u8], recorder:&mut Vec<u64>, prefix_len:usize,
                                        aes_rand:&AesRand, probe:&Box<dyn CodeTopoProbeMethodV6>, all_nodes:&mut AHashSet<u128>,
                                        output:&mut Box<dyn OutputMethod>, only_from_dest:bool) {

        // ipv6数据包(包括数据)的长度必须大于 40
        if 40 > net_layer_header_and_data.len() { return }
        // 网络层数据
        let net_layer_data = &net_layer_header_and_data[40..];

        match probe.receive_packet_v6(ts, net_layer_header_and_data, net_layer_data, aes_rand){
            Some(res) => {
                // 如果数据包验证通过

                // 如果 响应地址 和 目的地址 相等, 将被视为异常情况, 
                // 不统计该接口地址, 并且不参与reward计算
                if res.dest_ip == res.responder { return }
                
                if only_from_dest {
                    // 如果仅允许来自边缘设备的
                    if !res.from_destination {
                        // 如果不是边缘设备
                        return
                    }
                }

                // 输出该条目信息
                output.writer_line(&probe.print_record(&res));

                let code_vec = &res.code;
                let code = u32::from_be_bytes([0, code_vec[0], code_vec[1], code_vec[2]]) as usize;

                // 编码不能超过前缀总数量
                // 响应者必须为全新的
                if code >= prefix_len || all_nodes.contains(&res.responder) { return }
                
                // 如果没有该响应地址, 直接加入
                all_nodes.insert(res.responder);
                recorder[code] += 1;
            }
            None => return,
        }
    }
}