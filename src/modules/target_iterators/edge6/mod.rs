use rand_distr::Distribution;
use rand::prelude::SliceRandom;
use rand::rng;
use rand_distr::weighted::WeightedAliasIndex;
use crate::modules::target_iterators::scour6::thompson_window::ThompsonWindow;
use crate::modules::target_iterators::tree_trace::PCStable;
use crate::modules::target_iterators::TreeTraceIter;

pub struct EdgeIter6 {
    // 前缀信息结构表, 每个元素表示一个前缀, 其中是它的具体信息
    pub pcs_list:Vec<PCStable>,

    // 汤姆森采样 窗口大小
    pub window_size:u32,
    
    // 跳数限制大小
    pub hop_limit:u8,

    // 汤姆森窗口
    pub thompson_window:Vec<ThompsonWindow>,
}


impl EdgeIter6 {


    pub fn new(path:&String, window_size:u32, hop_limit:u8) -> Self {
        // 初始状态下的 pcs列表
        let initial_pcs_list = TreeTraceIter::init_pcs_list(path);
        let initial_pcs_list_len = initial_pcs_list.len();

        Self {
            pcs_list: initial_pcs_list,
            window_size,
            hop_limit,
            thompson_window: vec![ThompsonWindow::new(); initial_pcs_list_len],
        }
    }

    /// 在一个轮次的探测完成以后, 更新所有前缀的 reward
    pub fn update_rewards(&mut self, info:Vec<u64>){
        let window_size = self.window_size;
        for ((cur_pcs, reward_plus), cur_thompson_window) in self.pcs_list.iter_mut().zip(info).zip(self.thompson_window.iter_mut()) {
            
            // 警告: 这里把reward当本轮次生成数量用
            if cur_pcs.reward != 0 {

                // 当前轮该区域成功次数
                let cur_success = reward_plus as u32;
                // 当前轮该区域失败次数
                let cur_failure = (cur_pcs.reward as u32) - cur_success;

                // 更新窗口
                cur_thompson_window.update_window(cur_success, cur_failure, window_size);
                
                cur_pcs.reward = 0;
            }
        }
    }


    pub fn gen_target(&mut self, budget:u64) -> Vec<(u64, u8, Vec<u8>)>{
        let mut targets = Vec::with_capacity(budget as usize);

        // 获取采样器
        let (weight_index, indexes) =
            if let Some(w) =
                self.get_weight_index() { w } else { return Vec::new() };

        let hop_limit = self.hop_limit;
        let rng = &mut rng();
        for _ in 0..budget {

            // 根据分布进行随机抽取
            let chosen_index = weight_index.sample(rng);
            // 还原出 前缀区域 的下标
            let region_index = indexes[chosen_index];
            

            // 由索引找到对应 pcs块
            let tpcs = &mut self.pcs_list[region_index];

            // 将生成的目标加入队列
            // (目标前缀, hop_limit), 包含区域编码信息的自定义编码
            targets.push(tpcs.gen_edge_target(region_index as u32, hop_limit));
            
            // 注意这里是本轮次生成数量
            tpcs.reward += 1;
        }

        // 对所有目标打乱顺序
        targets.shuffle(rng);

        targets
    }



    fn get_weight_index(&self) -> Option<(WeightedAliasIndex<f64>, Vec<usize>)> {
        let pcs_list = &self.pcs_list;
        let prefix_len = pcs_list.len();
        let rng = &mut rng();

        let mut weights = Vec::with_capacity(prefix_len);
        let mut indexes = Vec::with_capacity(prefix_len);

        for (cur_index, cur_pcs) in pcs_list.iter().enumerate() {
            if cur_pcs.offset < cur_pcs.mask {

                // 将 汤姆森采样系数 作为权重
                let cur_win = &self.thompson_window[cur_index];
                let weight = cur_win.get_weight(rng);

                indexes.push(cur_index);
                weights.push(weight);
            }
        }

        if indexes.is_empty() {
            // 已经没有可用的区域
            None
        } else {
            Some((WeightedAliasIndex::new(weights).unwrap(), indexes))
        }
    }
    
}