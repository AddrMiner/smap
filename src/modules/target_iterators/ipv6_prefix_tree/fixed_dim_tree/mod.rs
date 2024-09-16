mod node;
mod init;
mod method;
mod node_expand;
mod gen_targets;
mod hier_prefix_tree;
mod update_tree_cascade;
mod update_tree_independent;

use std::cell::RefCell;
use std::rc::Rc;
use ahash::AHashMap;
use rust_decimal::Decimal;
use crate::modules::target_iterators::ipv6_prefix_tree::fixed_dim_tree::node::IPv6FixedPrefixNode;

/// ipv6固定维度前缀树
#[derive(Clone)]
pub struct IPv6FixedPrefixTree {

    // id 总数, 该值累增
    pub id_num:u64,

    // 空间树划分维度
    // 如 dim为4 意味着 以地址结构中连续4个比特为划分单位
    pub dim:u8,

    // 1usize << dim
    pub dim_size:usize,

    // 分割掩码
    // 后dim个二进制位为1, 其余为0
    // 如 当dim=4时, mask= 0...0_1111
    pub split_mask_u128:u128,
    pub split_mask_usize:usize,

    // 最大前缀长度
    // 即: 分割范围为 [1, 最大前缀长度]
    // 注意: 分割范围 应该被 划分维度 整除
    pub max_prefix_len:u8,


    // 前缀空间树根节点
    pub root:Option<Rc<RefCell<IPv6FixedPrefixNode>>>,

    // 初始分割点列表
    // 注意: 所有分割点列表都是从小到大排序的, 对应地址结构从右向左的顺序
    pub initial_split_move_len:Vec<u8>,


    // 当前分裂的节点队列
    // 注意: 事实上为本次探测的节点
    pub cur_tar_node_queue:Vec<Rc<RefCell<IPv6FixedPrefixNode>>>,

    // 当前节点队列
    pub node_queue:Vec<Rc<RefCell<IPv6FixedPrefixNode>>>,

    // 学习率
    pub learning_rate:Decimal,

    // 起始前缀长度
    pub start_prefix_len:u8,

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
    
    // 是否允许对空间树的同级节点进行扩展
    pub allow_layer_expand:bool,
    // 进行同级扩展时, 节点孩子数量需要大于的数量
    pub layer_expand_count:usize,
    // 层级分裂比例, 当节点的分支数量超过前q(比例)时, 对节点进行完全扩展
    pub layer_expand_ratio:f64,
    // 分裂数量
    pub split_count:Vec<u8>,
    
    // 分裂出零节点时, 父节点id -> 子零节点id
    pub cur_parent_id_to_zero_child_id:AHashMap<u64, u64>,
    
    // 节点队列随机化
    pub rand_ord:bool,
}