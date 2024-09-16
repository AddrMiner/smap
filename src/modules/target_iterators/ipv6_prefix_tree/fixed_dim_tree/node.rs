use std::cell::RefCell;
use std::rc::Rc;
use ahash::AHashMap;
use rust_decimal::Decimal;

pub struct IPv6FixedPrefixNode {

    // 节点唯一标识
    pub id:u64,

    // 节点模式, 当前节点前缀(后几位为0)
    pub mode:u128,
    
    // 是否为 零节点(即分裂处的地址结构块为0)
    pub zero:bool,

    // 该节点的子节点指针
    pub children:Vec<Rc<RefCell<IPv6FixedPrefixNode>>>,

    // 从 树的根节点 到 该节点位置 途径的所有分支节点的 id(有序)
    pub branches:Vec<u64>,

    // 前缀长度
    pub prefix_len:u8,
}

impl IPv6FixedPrefixNode {

    pub fn new(id:u64, mode:u128, prefix_len:u8, zero:bool) -> Self {
        Self {
            id,
            mode,
            zero,
            
            children: Vec::new(),
            branches: Vec::new(),

            prefix_len,
        }
    }

    /// 计算 当前节点的 奖励值(该节点所有关联节点的 q_value之和)
    /// 注意: 该函数应用于 按照q_value排序然后选择分裂节点之前
    pub fn get_q_value(&self, id_q_value:&AHashMap<u64, Decimal>) -> Decimal {
        
        let mut q_value = Decimal::from(1);

        for branch in &self.branches {
            q_value *= id_q_value.get(branch).unwrap();
        }
        
        q_value
    }
}

