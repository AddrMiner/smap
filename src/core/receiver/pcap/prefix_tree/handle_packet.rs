use ahash::AHashSet;
use crate::core::receiver::pcap::PcapReceiver;
use crate::modules::output_modules::OutputMethod;
use crate::modules::probe_modules::topology_probe::topo_mod_v6::TopoMethodV6;
use crate::modules::target_iterators::Ipv6VecDoubleTree;
use crate::tools::encryption_algorithm::aes::AesRand;

impl PcapReceiver {
    
    
    pub fn prefix_scan_handle_packet_v6(ts:&libc::timeval, net_layer_header_and_data:&[u8], double_tree_struct:&mut Ipv6VecDoubleTree,
                                        aes_rand:&AesRand, probe:&Box<dyn TopoMethodV6>, all_nodes:&mut AHashSet<u128>,
                                        output:&mut Box<dyn OutputMethod>) {
        
        // ipv6数据包(包括数据)的长度必须大于 40
        if 40 > net_layer_header_and_data.len() { return }
        // 网络层数据
        let net_layer_data = &net_layer_header_and_data[40..];

        match probe.parse_packet_v6(ts, net_layer_header_and_data, net_layer_data, aes_rand){
            Some(res) => {
                // 如果数据包验证通过
                
                // 交由 double_tree 算法处理
                if double_tree_struct.receive(&res, all_nodes) {
                    // 如果非 重复响应 或 异常
                    
                    // 输出该条目信息
                    output.writer_line(&probe.print_record(&res, net_layer_header_and_data));
                }
            }
            None => return,
        }
    }
}