use std::cell::RefCell;
use std::mem::take;
use std::rc::Rc;
use ahash::AHashMap;
use rand::rngs::ThreadRng;
use rand::seq::SliceRandom;
use rust_decimal::Decimal;

#[derive(Debug)]
pub struct IPv6PrefixNode {

    // 节点唯一标识
    pub id:u64,

    // 节点模式, 当前节点前缀(后几位为0)
    pub mode:u128,

    // 是否为 零节点(即分裂处的地址结构块为0)
    pub zero:bool,

    // 是否为实质节点
    // 实质节点是指 确实存在的前缀划分
    pub real:bool,

    // 该节点的子节点指针
    pub children:Vec<Rc<RefCell<IPv6PrefixNode>>>,

    // 从 树的根节点 到 该节点位置 途径的所有分支节点的 id(有序)
    // 警告: 一般只包含 实质节点
    pub branches:Vec<u64>,
    
    // 未完成标识
    // 当同一节点下的孩子数量过多时, 
    // 同一节点的目标将被拆分成多次
    pub incomplete:bool,

    // 前缀长度
    pub prefix_len:u8,
}


impl IPv6PrefixNode {

    pub fn new(id:u64, mode:u128, prefix_len:u8, zero:bool, real:bool) -> Self {

        Self {
            id,
            mode,
            zero,

            real,

            children: Vec::new(),
            branches: Vec::new(),
            // 未完成标识默认为 否
            incomplete: false,
            prefix_len,
        }
    }

    pub fn get_q_value(&self, id_q_value:&AHashMap<u64, Decimal>) -> Decimal {

        let mut q_value = Decimal::from(1);

        for branch in &self.branches {
            q_value *= id_q_value.get(branch).unwrap_or(&Decimal::from(1));
        }

        q_value
    }
    
    /// 取出 指定数量的目标节点
    /// 警告: 该函数只能对未完成节点使用
    pub fn get_targets(&mut self, num:usize) -> Vec<Rc<RefCell<IPv6PrefixNode>>> {
        if num < self.children.len() {
            self.children.drain(..num).collect()
        } else {
            // 当 需要的数量 >= 实际数量
            // 将 该节点 标记为 完成节点
            self.incomplete = false;
            
            take(&mut self.children)
        }
    }


    /// 通过层次遍历, 获取节点的 实质子节点
    pub fn get_children(&mut self, parent_branches:Vec<u64>, limit_num:usize, mut rng:&mut ThreadRng) 
    -> Vec<Rc<RefCell<IPv6PrefixNode>>> {
        
        // 实质节点队列
        let mut real_children: Vec<Rc<RefCell<IPv6PrefixNode>>> = Vec::new();

        // 存储广度优先遍历的节点队列
        let mut q: Vec<Rc<RefCell<IPv6PrefixNode>>> = take(&mut self.children);

        // 执行广度优先遍历
        while let Some(child_node) = q.pop() {
            let mut cur_child_node = child_node.borrow_mut();
            if cur_child_node.real {
                // 警告: 只有 实质节点 才能生成合法目标

                // 将 实质父节点的分支列表 和 本节点id 加入 本节点分支列表
                let cur_real_node_id = cur_child_node.id;
                cur_child_node.branches.extend(&parent_branches);
                cur_child_node.branches.push(cur_real_node_id);

                // 加入 队列
                real_children.push(child_node.clone());
                
            } else {
                // 注意: 非 实质节点 需要继续向下进行 广度优先遍历
                for next_child in &cur_child_node.children {
                    q.push(next_child.clone())
                }
            }
        }
        
        if real_children.len() > limit_num {
            // 如果 实质节点 数量过多
            
            // 进行随机化排序
            real_children.shuffle(&mut rng);
            let cur_targets = real_children.drain(..limit_num).collect();
            
            self.children = real_children;
            self.incomplete = true;
            
            cur_targets
        } else { 
            real_children
        }
    
    }
}