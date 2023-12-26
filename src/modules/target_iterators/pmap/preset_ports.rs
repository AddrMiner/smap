use crate::modules::target_iterators::pmap::graph::Graph;

/// 该数组中的顺序为优先顺序, 下标越低优先级越高, 该数组中存在的端口优先于其他端口
const PRESET_PORTS:[u16;30] = [80, 443, 7547, 22, 30005, 21, 123, 5060, 58000, 8080, 53, 25, 7170, 51005, 8089, 2000, 8443,3389, 554, 8008, 3306, 110, 8081, 23, 143, 587, 993, 47001, 4567, 50001];

impl Graph {

    /// 输入: 从小到大排序的目标端口  输出: 基于经验排序的目标端口
    pub fn sort_tar_ports(sorted_tar_ports:Vec<u16>) -> Vec<u16> {

        let mut preset_ports = vec![];
        let mut other_ports = vec![];

        for preset_port in PRESET_PORTS {
            if let Ok(_) = sorted_tar_ports.binary_search(&preset_port) {
                preset_ports.push(preset_port);
            }
        }

        for other_port in sorted_tar_ports {
            if !preset_ports.contains(&other_port) {
                other_ports.push(other_port);
            }
        }

        preset_ports.extend(other_ports);
        preset_ports
    }
}