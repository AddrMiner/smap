use ahash::AHashMap;
use crate::core::receiver::pcap::PcapReceiver;
use crate::modules::output_modules::OutputMethod;
use crate::modules::probe_modules::topo_mod_v6::CodeTopoProbeMethodV6;
use crate::tools::encryption_algorithm::aes::AesRand;

impl PcapReceiver {


    pub fn code_topo_prefix_scan_handle_packet_v6_2(ts:&libc::timeval, net_layer_header_and_data:&[u8], 
                                                     recorder:&mut Vec<u64>, recorder2:&mut Vec<AHashMap<u64, u128>>,
                                                    prefix_len:usize, aes_rand:&AesRand, probe:&Box<dyn CodeTopoProbeMethodV6>, 
                                                    all_nodes:&mut AHashMap<u128, u8>, output:&mut Box<dyn OutputMethod>) {

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
                
                // 输出该条目信息
                output.writer_line(&probe.print_record(&res));
                
                // 得到当前前缀索引
                let code_vec = &res.code;
                let tar_prefix_index = u32::from_be_bytes([0, code_vec[0], code_vec[1], code_vec[2]]) as usize;
                // 编码不能超过前缀总数量
                if tar_prefix_index >= prefix_len { return }
                
                
                
                
                // 记录未出现过的响应者 或 更新响应者的响应跳数为更小值
                if let Some(c) = all_nodes.get_mut(&res.responder) {
                    // 如果 以前记录过这个响应者
                    
                    if res.init_ttl < *c {
                        // 如果 当前响应跳数 小于 之前响应的跳数
                        *c = res.init_ttl;
                    }
                } else { 
                    // 如果 之前从未出现过 这个响应者, 首次添加
                    all_nodes.insert(res.responder, res.init_ttl);

                    // 为 该前缀增加reward
                    recorder[tar_prefix_index] += 1;

                    if !res.from_destination {
                        // 注意: 必须是路径上的路由器
                        // 对应前缀的地址信息块
                        let cur_dest_recorder = &mut recorder2[tar_prefix_index];

                        // 计算 目的地址的前64位前缀
                        let dest_prefix = (res.dest_ip >> 64) as u64;

                        // 创建  目标前缀 -> 首次响应者 的关联关系
                        cur_dest_recorder.insert(dest_prefix, res.responder);
                    }
                }
            }
            None => return,
        }
    }
}