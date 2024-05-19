use std::cell::RefCell;
use std::rc::Rc;
use ahash::AHashSet;

/// ipv6地址空间树叶子节点(种子地址聚类区域)
#[derive(Clone)]
pub struct IPv6SpaceTreeNode {
    
    // 标识
    pub id:u32,

    // 父节点指针
    pub parent:Option<Rc<RefCell<IPv6SpaceTreeNode>>>,

    // 节点层级
    pub level:u8,

    // 该节点的种子节点指针
    pub childs:Vec<Rc<RefCell<IPv6SpaceTreeNode>>>,

    // 该聚类区域的 种子地址
    // 初始化空间树 以及 第一次生成地址时使用, 后续将被置空
    pub seed_addrs_list:Vec<u128>,

    // 该节点的分裂点
    pub split_move_len:u8,
    // 该节点分裂点上的统计信息
    pub act_val_num:Vec<(usize, u64)>,

    // 该区域的 [剩余]分割维度栈(包括零熵值位)
    // 警告: 所有维度按 右移距离 表示
    // 注意: 该栈的顺序为  低熵 -> 高熵
    // 注意: 当熵值相等时为    地址结构较右 ->  地址结构较左
    pub split_stack:Vec<u8>,
    
    
    // 已经搜索过的维度数量(在维度栈中)
    pub searched_dim:u8,


    // 生成但未使用的地址
    // 注意: 使用后的地址应从该列表删除
    pub no_used_generated_address:AHashSet<u128>,


    // 区域模式 列表
    pub modes:Vec<u128>,
    
    // 区域地址生成元
    // 注意: 这里的 地址生成元 与 乘法循环群 的不同
    // 这里的 地址生成元 是 左移位数列表   顺序： 按照地址结构顺序 从右向左
    // 如:   0000_1111_0000_1111_0000_0000 对应的生成元为    [ 8, 16 ]
    pub gen_move_len:Vec<u8>,

    // 该区域地址空间大小  例: 16^(扩展的分裂点数) * 现有的模式串数量
    pub space_size:usize,

    // 该区域已经使用的地址
    // 注意: 第一次生成的地址必然包含全部种子地址, 后续也是, used_addrs应始终包含 种子地址
    pub used_addrs:AHashSet<u128>,

    // 区域Q值, 用于反馈更新
    pub q_value:f64,
}


impl IPv6SpaceTreeNode {
    
    pub fn new(id:u32,seed_addrs_list:Vec<u128>,
           split_stack:Vec<u8>, split_move_len:u8, act_val_num:Vec<(usize, u64)>,
           parent:Option<Rc<RefCell<IPv6SpaceTreeNode>>>, level:u8) -> Self {
        
        Self {
            id,
            parent,

            // 任何节点生成时, 孩子节点都为空
            level,
            childs: Vec::new(),
            
            seed_addrs_list,
            split_move_len,
            act_val_num,
            split_stack,
            
            // 初始化节点的searched_dim属性为0,表示该节点已被搜索的维度数
            searched_dim: 0,
            // 未使用的生成地址, 初始化为 空集合
            no_used_generated_address: AHashSet::new(),
            // 模式列表, 初始化为 空列表
            modes: Vec::new(),
            // 地址生成元, 由 扩展的模式维度 确定, 初始化为 空
            gen_move_len: Vec::new(),
            // 该节点代表的地址空间的大小, 初始化为 0
            space_size: 0,
            // 已经使用的地址, 初始化为 空
            used_addrs: AHashSet::new(),
            // 奖励值, 初始化(叶子节点)为  该节点总的种子数量 / 未分配维度数量
            q_value: 0.0,
        }
    }
}