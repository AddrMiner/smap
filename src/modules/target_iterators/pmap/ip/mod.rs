mod tools;
mod receiver;
mod sender;
use std::sync::Arc;
use crate::modules::target_iterators::pmap::state::State;

#[derive(Clone)]
pub struct IpStruct {

    // 状态指针
    pub state:Option<Arc<State>>,

    // 绝对概率表索引
    pub ab_index:usize,
    // 状态概率表索引
    pub state_index:usize,
    // 预设端口向量 索引, 用来对超出概率相关图范围的端口进行推荐
    pub preset_ports_index:usize,
    // 全端口空间端口迭代值, 初始值为0, 最大值为65535, 每次加一
    pub all_port:u16,

    // 当前地址已被 探活 的端口
    pub open_ports:Vec<u16>,
    // 当前地址已被探明 非活跃 的端口
    pub not_open_ports:Vec<u16>,

    // 是否保持状态标志
    // 如果为 true, 在获取 推荐端口 时, 相对概率表索引将被顺延
    // 如果为 false, 在获取 推荐端口 时, 相对概率表索引将被置为0
    pub remain_state:bool,

    // 预设端口向量 可用标记, 当预设向量中的所有端口都被推荐完后, 该标志会置否
    pub preset_ports_avail:bool,

    // 当前轮次发送的端口
    pub cur_sent_port:u16,
}


impl IpStruct {

    pub fn new() -> Self {

        Self {
            state: None,

            ab_index: 0,
            state_index: 0,
            preset_ports_index: 0,
            all_port: 0,

            open_ports: Vec::new(),
            not_open_ports: Vec::new(),

            remain_state: true,
            preset_ports_avail: true,
            cur_sent_port: 0,
        }
    }
}

