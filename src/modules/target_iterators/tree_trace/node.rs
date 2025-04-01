use std::cmp::Ordering;
use std::collections::BinaryHeap;
use num_traits::FromPrimitive;
use ordered_float::NotNan;
use crate::modules::target_iterators::tree_trace::pcs_table::PCStable;

#[derive(Debug, Eq, PartialEq)]
pub struct HuffNode {

    // 左子树
    pub zero:Option<Box<HuffNode>>,

    // 右子树
    pub one:Option<Box<HuffNode>>,

    // 权重
    pub weight:NotNan<f64>,

    // 前缀索引
    pub index:u32,
}

impl Ord for HuffNode {
    fn cmp(&self, other: &Self) -> Ordering {
        other.weight.cmp(&self.weight)
    }
}

impl PartialOrd for HuffNode {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl HuffNode {


    /// 搜索哈夫曼树, 由随机字符找出对应的  前缀索引
    pub fn search_tree(node:&HuffNode, bitstream:u64) -> u32 {

        if node.index != u32::MAX {
            // 非叶子节点都为max, 非0即为叶子节点
            return node.index;
        }

        if bitstream&1 == 0 {
            let zero = node.zero.as_ref().unwrap();
            Self::search_tree(zero, bitstream>>1)
        } else {
            let one = node.one.as_ref().unwrap();
            Self::search_tree(one, bitstream>>1)
        }
    }


    /// 以 pcs(前缀信息列表) 为基础, 生成哈夫曼树, 并返回哈夫曼树的根节点
    pub fn new(pcs_table:&Vec<PCStable>, gen_topo_tar:bool) -> Option<HuffNode> {
        let mut heap = BinaryHeap::new();

        if gen_topo_tar {
            // 如果生成拓扑探测的目标
            for (index, cur_pcs) in pcs_table.iter().enumerate() {
                // 警告: offset的后5位用来生成ttl
                if cur_pcs.offset < cur_pcs.mask {

                    let weight = ((20 + cur_pcs.reward) as f64) / (((1000 + cur_pcs.offset) as f64).log2());

                    heap.push(HuffNode {
                        zero: None,
                        one: None,
                        weight: NotNan::from_f64(weight).unwrap(),
                        index: index as u32,
                    })
                }
            }
        } else {
            // 如果生成散点图目标
            for (index, cur_pcs) in pcs_table.iter().enumerate() {
                // 警告: offset的后5位用来生成ttl
                if (cur_pcs.offset >> 5) < cur_pcs.mask {

                    let weight = ((20 + cur_pcs.reward) as f64) / (((1000 + cur_pcs.offset) as f64).log2());

                    heap.push(HuffNode {
                        zero: None,
                        one: None,
                        weight: NotNan::from_f64(weight).unwrap(),
                        index: index as u32,
                    })
                }
            }
        }

        // 生成哈夫曼树
        while heap.len() > 1 {
            // 获取权重最小的节点
            let zero = heap.pop().unwrap();
            // 获取权重次小的节点
            let one = heap.pop().unwrap();

            let new_node = HuffNode {
                weight: zero.weight + one.weight,

                zero: Some(Box::new(zero)),
                one: Some(Box::new(one)),

                index: u32::MAX,
            };

            heap.push(new_node);
        }

        // 取出优先列表中的最后一个节点, 也是哈夫曼树的根节点
        heap.pop()
    }

}