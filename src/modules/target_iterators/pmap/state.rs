
use ahash::AHashMap;
use crate::modules::target_iterators::pmap::graph::Graph;
use crate::tools::others::sort::quick_sort_from_big_to_small;

pub struct State {
    // 相对概率表   按照 相对概率 从大到小的顺序排列
    pub ports:Vec<PortPro>,
    // 端口号 -> 相对概率表索引
    pub port_to_ptr:AHashMap<u16, u16>
}

#[derive(Clone)]
pub struct PortPro {
    // 端口号
    pub port:u16,
    // 该端口对应的相对概率
    pub probability:f64,
}

impl State {

    /// 使用 当前活跃端口 从 空状态 创建状态
    pub fn new_state_from_none(cur_port:u16, graph:&Graph) -> Self {

        // 保存相对概率信息的临时向量
        let mut pro_vec = Vec::new();
        // 按 概率值从大到小 排列的 端口, 概率 对
        let mut new_ports = Vec::new();

        // 当前端口 对应的总计数值
        let cur_single_cnt = match graph.single_cnt.get(&cur_port) {
            // 如果存在, 直接取出
            Some(c) => *c as f64,
            // 如果不存在对应的 总计数值
            // 说明 概率相关图对该端口一无所知
            None => {
                return Self {
                    ports: vec![],
                    port_to_ptr: AHashMap::with_capacity(0),
                }
            }
        };

        // 当前端口的  关系端口, 及其计数值 组成的映射
        let cur_map =  match graph.both_cnt.get(&cur_port) {
            // 如果存在, 直接取出
            Some(c) => c,
            // 如果不存在对应的 关系映射
            // 说明 该节点在图数据结构中独立
            None => {
                return Self {
                    ports: vec![],
                    port_to_ptr: AHashMap::with_capacity(0),
                }
            }
        };

        for (dport, dport_cnt) in cur_map {

            let dport = *dport;

            // 关系端口在 当前端口 开放下开放的 相对概率
            // 相对概率 = 关系端口在当前端口开放下的计数 / 当前端口的开放总计数
            let re_pro = (*dport_cnt as f64) / cur_single_cnt;

            if re_pro > graph.port_to_ab_probability[dport as usize] {
                // 如果 关系端口 在 当前端口开放下的 相对概率
                // 大于
                // 该端口本身的绝对概率

                pro_vec.push(re_pro);
                new_ports.push(PortPro { port: dport, probability: re_pro });
            }
        }

        let new_ports_len = pro_vec.len();
        if new_ports_len == 0 {
            // 如果不存在 对应端口
            // 直接返回 空状态

            return Self {
                ports: vec![],
                port_to_ptr: AHashMap::with_capacity(0),
            }
        }

        let pro_vec_sub_one = pro_vec.len() - 1;
        quick_sort_from_big_to_small(&mut pro_vec, &mut new_ports, 0, pro_vec_sub_one);

        // 创建索引:  端口号 -> 相对概率表索引
        let mut ptr_map = AHashMap::new();
        for i in 0..new_ports_len {
            ptr_map.insert(new_ports[i].port, i as u16);
        }

        Self {
            ports: new_ports,
            port_to_ptr: ptr_map,
        }
    }


    pub fn new_state_from_exist(cur_port:u16, pre_state:&State, graph:&Graph) -> Self {

        // 复制 原状态 中的 端口信息
        let mut cur_ports:Vec<PortPro> = pre_state.ports.clone();

        // 保存 新端口信息 的向量
        let mut new_update:Vec<PortPro> = Vec::new();

        // 当前端口 对应的总计数值
        let cur_single_cnt = match graph.single_cnt.get(&cur_port) {
            // 如果存在, 直接取出
            Some(c) => *c as f64,
            // 如果不存在对应的 总计数值
            // 说明 概率相关图对该端口一无所知
            None => {
                return Self {
                    ports: vec![],
                    port_to_ptr: AHashMap::with_capacity(0),
                }
            }
        };

        // 当前端口的  关系端口, 及其计数值 组成的映射
        let cur_map =  match graph.both_cnt.get(&cur_port) {
            // 如果存在, 直接取出
            Some(c) => c,
            // 如果不存在对应的 关系映射
            // 说明 该节点在图数据结构中独立
            None => {
                return Self {
                    ports: vec![],
                    port_to_ptr: AHashMap::with_capacity(0),
                }
            }
        };

        for (dport, dport_cnt) in cur_map {

            // 关系端口在 当前端口 开放下开放的 相对概率
            // 相对概率 = 关系端口在当前端口开放下的计数 / 当前端口的开放总计数
            let re_pro = (*dport_cnt as f64) / cur_single_cnt;

            if let Some(p) = pre_state.port_to_ptr.get(dport) {
                // 如果 当前端口 的 关系端口 在 原状态 中存在

                let dport_index = *p as usize;

                // 如果 对应端口 当前的相对概率  大于  之前状态中的 对应相对概率
                if re_pro > cur_ports[dport_index].probability {
                    cur_ports[dport_index].probability = re_pro;
                }
            } else {
                // 如果 当前端口 的 关系端口 在 原状态 中不存在

                let d_port = *dport;
                if re_pro > graph.port_to_ab_probability[d_port as usize] {
                    new_update.push(PortPro { port: d_port, probability: re_pro })
                }
            }
        }

        // 合并 原状态端口信息 和 新增端口信息
        cur_ports.extend(new_update);

        let cur_ports_len = cur_ports.len();

        // 保存 端口概率信息 的临时向量
        let mut tmp_pro_info:Vec<f64> = Vec::with_capacity(cur_ports_len);

        // 遍历 端口信息向量, 并将 端口概率 按顺序存储到 临时概率信息向量 中
        for cur_port_info in cur_ports.iter() {
            tmp_pro_info.push(cur_port_info.probability);
        }

        // 按照 概率从大到小的顺序 对 端口信息向量进行排序
        // 注意: 这里使用快速排序, 修改时应仔细斟酌使用哪种排序算法
        quick_sort_from_big_to_small(&mut tmp_pro_info, &mut cur_ports, 0, cur_ports_len-1);

        // 重新计算 指针映射   端口号 -> 相对概率表索引
        let mut ptr_map = AHashMap::with_capacity(cur_ports_len);
        for i in 0..cur_ports_len {
            ptr_map.insert(cur_ports[i].port, i as u16);
        }

        Self {
            ports: cur_ports,
            port_to_ptr: ptr_map,
        }

    }
}