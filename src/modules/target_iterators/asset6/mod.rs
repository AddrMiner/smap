mod node;
mod init;
mod method;
mod node_method;
mod tools;
mod density_space_tree;
mod get_addrs;
mod aliased_check;

use std::cell::RefCell;
use std::rc::Rc;
use ahash::{AHashMap, AHashSet};
use uint::construct_uint;
use crate::modules::target_iterators::asset6::node::IPv6PortSpaceTreeNode;


construct_uint! {
	pub struct U144(3);
}

#[derive(Clone)]
pub struct IPv6PortSpaceTree {

    // id 总数, 该值累增
    pub id_num:u32,

    // 空间树划分维度
    // 如 dim为4 意味着 以地址结构中连续4个比特为划分单位
    pub dim:u32,

    // 1usize << dim
    pub dim_size:usize,

    // 分割掩码
    // 后dim个二进制位为1, 其余为0
    // 如 当dim=4时, mask= 0...0_1111
    pub split_mask_u144:U144,
    
    // 空间树 根节点
    pub root:Option<Rc<RefCell<IPv6PortSpaceTreeNode>>>,

    // 叶子节点最大空间
    pub max_leaf_size:usize,

    // 初始分割点列表
    // 注意: 所有分割点列表都是从小到大排序的, 对应地址结构从右向左的顺序
    pub initial_split_move_len:Vec<u8>,

    // 聚类区域队列
    pub region_queue:Vec<Rc<RefCell<IPv6PortSpaceTreeNode>>>,

    // 与 聚类区域队列 对应的 奖励值队列
    pub all_reward:Vec<f64>,

    // 区域抽取数量
    pub region_extraction_num:u32,

    // 学习率
    pub learning_rate:f64,

    // 种子路径
    pub seeds_path:String,


    // 不允许生成种子地址中的地址
    pub no_allow_gen_seeds:bool,
    // 凡是输入文件中的地址都不允许生成
    pub no_allow_gen_seeds_from_file:bool,


    // 使用过的地址 的 总集合
    pub used_addrs:AHashSet<U144>,

    // 当前 抽取区域数量
    // 警告: 该值在每轮次生成地址时重置
    pub cur_extra_region_num:usize,

    // 种子数量
    pub seeds_num:usize,
    
    
    // 聚类分块 -> 端口
    // 在聚类后使用
    pub id2port:AHashMap<u16, u16>,
    
    
    // 端口熵值参数
    pub port_entropy_mul:f64,
    
    // 判断别名的阈值
    pub aliased_threshold:u64,
    
    // 端口扫描标志字段
    pub port_scan_flag:u8,
    
    // 别名解析标志字段
    pub aliased_scan_flag:u8,
    
    // 保存别名前缀的路径
    pub aliased_prefixes_path:Option<String>,
    
    // 
}