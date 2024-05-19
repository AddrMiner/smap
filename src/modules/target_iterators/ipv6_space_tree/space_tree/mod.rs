mod init;
mod method;
mod node;
mod tools;
mod node_method;

use std::cell::RefCell;
use std::rc::Rc;
use ahash::AHashSet;
pub use crate::modules::target_iterators::ipv6_space_tree::space_tree::node::IPv6SpaceTreeNode;

/// ipv6地址空间树
#[derive(Clone)]
pub struct IPv6SpaceTree {
    
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
    pub split_mask_u128:u128,
    pub split_mask_usize:usize,
    
    // 分割范围
    pub range:(u32, u32),
    
    
    // 空间树 根节点
    pub root:Option<Rc<RefCell<IPv6SpaceTreeNode>>>,

    // 叶子节点最大空间
    pub max_leaf_size:usize,

    // 初始分割点列表
    // 注意: 所有分割点列表都是从小到大排序的, 对应地址结构从右向左的顺序
    pub initial_split_move_len:Vec<u8>,

    // 聚类区域队列
    pub region_queue:Vec<Rc<RefCell<IPv6SpaceTreeNode>>>,
    // 与 聚类区域队列 对应的 奖励值队列
    pub all_reward:Vec<f64>,
    

    // 区域抽取数量
    pub region_extraction_num:u32,

    // 学习率
    pub learning_rate:f64,
    
    // 种子地址路径
    pub seeds_path:String,
    
    // 不允许生成种子地址中的地址
    pub no_allow_gen_seeds:bool,
    // 凡是输入文件中的地址都不允许生成
    pub no_allow_gen_seeds_from_file:bool,
    
    // 使用过的地址 的 总集合
    pub used_addrs:AHashSet<u128>,
    
    // 当前 抽取区域数量
    // 警告: 该值在每轮次生成地址时重置
    pub cur_extra_region_num:usize,
    
    // 种子数量
    pub seeds_num:usize,
}
