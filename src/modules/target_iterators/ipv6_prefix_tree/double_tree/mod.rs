mod receive;
mod gen_targets;


use std::process::exit;
use ahash::AHashMap;
use log::error;
use crate::SYS;


pub struct Ipv6VecDoubleTree {

    // 初始ttl
    pub initial_ttl:u8,
    // 最大连续沉默数量
    pub gap_limit:u8,
    // 最大ttl
    pub max_ttl:u8,
    // 最小目标数量
    pub min_target_num:usize,

    // 阶段计数
    pub phase:u8,

    // 本轮次要探测的目标地址
    pub addrs:Vec<u128>,
    // 地址 -> 节点队列索引 的映射
    pub addr_to_seq:AHashMap<u128, usize>,

    // 地址对应的状态
    // 注意: 该列表顺序与 节点队列 顺序保持一致
    pub states:Vec<(u8, u8)>,
    pub cur_no_recv:Vec<(bool, bool)>,
    pub silent_count:Vec<u8>,

    // 地址对应的 (命中次数, 已使用数据包数量)
    // 注意: 该列表顺序与 节点队列 顺序保持一致
    pub reward_used:Vec<(u64, u64)>,
}


impl Ipv6VecDoubleTree {
    pub fn new(initial_ttl:u8, gap_limit:u8, max_ttl:u8, min_target_num:usize) -> Self {
        
        // 最大ttl不得超过64
        if max_ttl > 64 { error!("{}", SYS.get_info("err", "topo_max_ttl_err"));exit(1) }
        
        Self {
            initial_ttl,
            gap_limit,
            max_ttl,
            min_target_num,

            // 注意: 阶段初始化为0
            phase: 0,

            addrs: Vec::new(),
            addr_to_seq: AHashMap::new(),
            states: Vec::new(),
            cur_no_recv: Vec::new(),
            silent_count: Vec::new(),
            reward_used: Vec::new(),
        }
    }


    pub fn set_targets(&mut self, addrs:Vec<u128>, addr_to_seq:AHashMap<u128, usize>){
        let addrs_len = addrs.len();

        self.addrs = addrs;
        self.addr_to_seq = addr_to_seq;

        // 注意: 阶段初始化为0
        self.phase = 0;

        // 将 (后退状态, 前进状态) 设为 (初始ttl, 初始ttl + 1)
        let initial_ttl = self.initial_ttl;
        self.states = vec![(initial_ttl, initial_ttl); addrs_len];
        
        // 连续沉默计数
        self.silent_count = vec![0; addrs_len];

        // 将 当前轮次是否 已经接收
        // 注意: true代表未接收
        self.cur_no_recv = vec![(true, true); addrs_len];
        // 将 (命中次数, 已使用数据包数量) 设为 (0, 1)
        self.reward_used = vec![(0u64, 1u64); addrs_len];
    }
}