use crate::modules::target_iterators::ipv6_space_tree::space_tree::IPv6SpaceTree;

impl IPv6SpaceTree {

    /// 获取概率向量对应的熵值
    /// 输入: 频率向量, 归一化除数
    /// 警告: 计算熵值时请勿传入 小于等于0的概率值
    #[inline]
    pub fn get_entropy(pro_list:Vec<f64>, norm:f64) -> f64 {

        let mut sum:f64 = 0.0;
        for p in pro_list.into_iter() {
            sum += p * p.log2();
        }
        
        -sum / norm
    }


    /// 获取频数对应的概率向量
    /// 输入: 总数量, 频数向量
    /// 警告: 将自动删除频数为0的项
    #[inline]
    pub fn get_pro_list_no_zero(total_num:f64, val_num:&Vec<u64>) -> Vec<f64> {

        // 初始化 概率列表
        let mut pro_list:Vec<f64> = Vec::with_capacity(val_num.len());

        // 不保留频数为0的项
        for &n in val_num {
            if n > 0 {
                let pro = (n as f64) / total_num;
                pro_list.push(pro);
            }
        }
        
        pro_list
    }

    
    /// 计算 对应数量非0的值, 及其对应频数
    pub fn get_act_val_num(stat:&Vec<u64>) -> Vec<(usize, u64)> {
        let mut act_val_num:Vec<(usize, u64)> = vec![];
        for (val, &num) in stat.into_iter().enumerate() {
            if num != 0 {
                act_val_num.push((val, num));
            }
        }
        act_val_num
    }
    
    
    
}