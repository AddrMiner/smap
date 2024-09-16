use std::cell::RefCell;
use std::rc::Rc;
use ahash::AHashMap;
use rust_decimal::Decimal;
use crate::modules::target_iterators::ipv6_prefix_tree::prefix_tree::node::IPv6PrefixNode;

mod init;
mod node;
mod method;
mod hier_prefix_tree;
mod gen_targets;
mod update_tree_cascade;
mod node_expand;
mod update_tree_independent;

/// ipv6 维度空间树
#[derive(Clone)]
pub struct IPv6PrefixTree {

    // id 总数, 该值累增
    pub id_num:u64,

    // 空间树 默认划分维度
    // 如 进行子空间扩展时扩展的维度大小
    // 警告: 在有信息区域，不使用默认维度
    pub default_dim:u8,

    // 1usize << dim
    // 默认维度大小
    pub default_dim_size:usize,


    // 起始前缀长度
    pub start_prefix_len:u8,
    // 最大前缀长度
    pub max_prefix_len:u8,


    // 前缀空间树根节点
    pub root:Option<Rc<RefCell<IPv6PrefixNode>>>,


    // 当前分裂的节点队列
    // 注意: 事实上为本次探测的节点
    pub cur_tar_node_queue:Vec<Rc<RefCell<IPv6PrefixNode>>>,

    // 当前节点队列
    pub node_queue:Vec<Rc<RefCell<IPv6PrefixNode>>>,

    // 学习率
    pub learning_rate:Decimal,
    

    // 种子地址路径
    pub seeds_path:String,
    // 前缀列表路径
    pub prefix_path:String,


    // 节点id 对应的 q_value
    pub id_q_value:AHashMap<u64, Decimal>,

    // 小于等于 该阈值 的节点将被直接移除
    pub threshold:Option<Decimal>,

    // 每次抽取的节点数量
    pub extra_node_num:usize,

    // 是否允许未到最大前缀长度的叶子节点进行扩展
    pub allow_leaf_expand:bool,

    // 分裂出零节点时, 父节点id -> 子零节点id
    pub cur_parent_id_to_zero_child_id:AHashMap<u64, u64>,
    
    // 同一父节点单次释放的最大子节点数量
    pub child_max_size:usize,

    // 节点队列随机化
    pub rand_ord:bool,
}