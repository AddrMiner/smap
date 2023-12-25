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
    // 相对概率表索引
    pub state_index:usize,
    // 目标端口向量 索引, 用来对超出概率相关图范围的端口进行推荐
    pub tar_ports_index:usize,

    // 当前地址已被 探活 的端口
    pub open_ports:Vec<u16>,
    // 当前地址已被探明 非活跃 的端口
    pub not_open_ports:Vec<u16>,

    // 是否保持状态标志
    // 如果为 true, 在获取 推荐端口 时, 相对概率表索引将被顺延
    // 如果为 false, 在获取 推荐端口 时, 相对概率表索引将被置为0
    pub remain_state:bool,

    // 当前轮次发送的端口
    pub cur_sent_port:u16,
}


impl IpStruct {

    pub fn new() -> Self {

        Self {
            state: None,

            ab_index: 0,
            state_index: 0,
            tar_ports_index: 0,

            open_ports: Vec::new(),
            not_open_ports: Vec::new(),

            remain_state: true,
            cur_sent_port: 0,
        }
    }
}

