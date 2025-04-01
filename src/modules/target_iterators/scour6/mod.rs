
use rayon::iter::{IntoParallelIterator, ParallelIterator};
use rayon::iter::IndexedParallelIterator;
use std::mem::take;
use std::sync::Arc;
use ahash::{AHashMap, AHashSet};
use rand::prelude::Distribution;
use rand::rng;
use rand::seq::SliceRandom;
use rand_distr::weighted::WeightedAliasIndex;
use rayon::iter::IntoParallelRefMutIterator;
pub use crate::modules::target_iterators::scour6::pcs_plus_table::PCSPlusTable;
use crate::modules::target_iterators::scour6::pcs_plus_table::PcsState;
use crate::modules::target_iterators::scour6::thompson_window::ThompsonWindow;
use crate::modules::target_iterators::TreeTraceIter;

mod pcs_plus_table;
mod tools;
mod target_gen;
mod state;
pub mod thompson_window;

pub struct Scour6Iter {

    // 前缀信息结构表(加强版), 每个元素表示一个前缀, 其中是它的具体信息
    pub pcs_list:Vec<PCSPlusTable>,
    
    // 最大分割点幂数
    pub sample_pow:u8,
    
    // 汤姆森采样 窗口大小
    pub window_size:u32,
    
    // 起始ttl, 传统为3, 建议为7或8
    pub start_ttl:u8,
}


impl Scour6Iter {
    pub fn new(path: &String, sample_pow: u64, window_size:u32, start_ttl:u8) -> Self {

        // 初始状态下的 pcs列表
        let initial_pcs_list = Self::init_pcs_list(path, sample_pow);

        Self {
            pcs_list: initial_pcs_list,
            sample_pow: sample_pow as u8,
            window_size,
            start_ttl,
        }
    }

    /// 将 得到响应的目的地址及其关联目的地址 写入pcs
    pub fn update_info(&mut self, recorder: Vec<u64>, recorder2: Vec<AHashMap<u64, u128>>, all_nodes: AHashMap<u128, u8>, expand_ttl_b:u32, expand_ttl_a:u32, ) -> AHashMap<u128, u8> {
        // 所有已知响应
        let all_nodes = Arc::new(all_nodes);
        
        let start_ttl = self.start_ttl;
        let sample_pow = self.sample_pow;
        let window_size = self.window_size;

        // 将pcs的所有权转移到本地
        let mut pcs_list = take(&mut self.pcs_list);

        (&mut pcs_list, recorder, recorder2).into_par_iter()
            .for_each(|(cur_pcs, cur_reward_plus, cur_prefix_info)| {
                
                if cur_pcs.cur_gen_num != 0 {
                    // 如果 当前该区域生成数量不为0时
                    
                    // 增加奖励值
                    cur_pcs.reward += cur_reward_plus;

                    for prefix_responder in cur_prefix_info.into_iter() {
                        // 遍历该大前缀下的每个子前缀
                        cur_pcs.dest_info.push(prefix_responder);
                    }

                    // 检查当前前缀信息块
                    cur_pcs.check(&all_nodes, sample_pow, start_ttl, expand_ttl_b, expand_ttl_a);
                    
                    // 当前轮该区域成功次数
                    let cur_success = cur_reward_plus as u32;
                    // 当前轮该区域失败次数
                    let cur_failure = cur_pcs.cur_gen_num - cur_success;
                    // 更新窗口
                    cur_pcs.thompson_window.update_window(cur_success, cur_failure, window_size);
                    
                    // 将所有生成数量不为0的区域的生成计数重置为0, 等待所有区域重新生成
                    cur_pcs.cur_gen_num = 0;
                }

                // 如果整个前缀空间耗尽
                if (cur_pcs.offset >> 5) > cur_pcs.mask {
                    if cur_pcs.not_finished {
                        // 之前未被标记过
                        cur_pcs.clear();
                        cur_pcs.not_finished = false;
                    }
                } else {
                    match cur_pcs.pcs_state {
                        PcsState::SECOND | PcsState::THIRD => {
                            // 如果是第二或第三状态
                            if cur_pcs.cur_sub_prefix_info.is_empty() {
                                // 在这两种状态下，如果为空则意味着已经完全探测
                                if cur_pcs.not_finished {
                                    // 之前未被标记过
                                    cur_pcs.clear();
                                    cur_pcs.not_finished = false;
                                }
                            }
                        }
                        PcsState::FIRST => {}
                    }
                }
            });

        // 归还 pcs
        self.pcs_list = pcs_list;

        // 将arc指针进行拆解并返回所有记录者
        Arc::try_unwrap(all_nodes).unwrap()
    }


    /// 生成指定数量的具体目标
    pub fn gen_target(&mut self, budget: usize) -> Vec<(u64, u8, Vec<u8>)> {
        // 将 pcs_list 移动到本地
        let mut pcs_list = take(&mut self.pcs_list);

        // 获取采样器
        let (weight_index, indexes) = 
            if let Some(w) = 
                Self::get_weight_index(&pcs_list) { w } else { return Vec::new() };
        
        let start_ttl = self.start_ttl;
        
        // 记录所有生成目标
        let mut all_targets = Vec::with_capacity(budget * 2);
        loop {
            // 获取分配数量
            let alloc = Self::get_alloc(&weight_index, &indexes, budget);
            
            let cur_all_targets: Vec<(u64, u8, Vec<u8>)> = pcs_list.par_iter_mut().enumerate()
                .flat_map(|(index, cur_pcs)| {
                    if let Some(b) = alloc.get(&index) {
                        // 如果分配了预算, 按预算执行
                        let b = *b;
                        let code = PCSPlusTable::get_prefix_code(index as u32);
                        let mut cur_targets = Vec::with_capacity(b);

                        for _ in 0..b {
                            let (cur_target, cur_hop_limit) = cur_pcs.gen_target(start_ttl);

                            if cur_target != 0 {
                                cur_targets.push((cur_target, cur_hop_limit, code.clone()));
                            }
                        }
                        
                        // 将 生成的目标 进行计数
                        cur_pcs.cur_gen_num += cur_targets.len() as u32;

                        cur_targets
                    } else {
                        // 没有分配预算就直接退出
                        Vec::new()
                    }
                }).collect();

            all_targets.extend(cur_all_targets);
            
            if pcs_list.len() == 1 {
                // 如果只有一个前缀
                let cur_pcs = &pcs_list[0];
                if (cur_pcs.offset >> 5) >= cur_pcs.mask {
                    break
                }
            }

            // 只有确认生成的目标数量达到要求才会退出
            if all_targets.len() >= budget { break }
        }

        // 保存所有 pcs
        self.pcs_list = pcs_list;

        // 对所有目标打乱顺序
        let mut rng = rng();
        all_targets.shuffle(&mut rng);

        all_targets
    }

    fn get_weight_index(pcs_list: &Vec<PCSPlusTable>) -> Option<(WeightedAliasIndex<f64>, Vec<usize>)> {
        let prefix_len = pcs_list.len();
        let rng = &mut rng();
        
        let mut weights = Vec::with_capacity(prefix_len);
        let mut indexes = Vec::with_capacity(prefix_len);

        for (cur_index, cur_pcs) in pcs_list.iter().enumerate() {
            if cur_pcs.not_finished {

                // 将 汤姆森采样系数 作为权重
                let weight = cur_pcs.thompson_window.get_weight(rng);

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
    
    fn get_alloc(weight_index:&WeightedAliasIndex<f64>, indexes: &Vec<usize>, budgets:usize) -> AHashMap<usize, usize>{
        let rng = &mut rng();
        
        let mut alloc = AHashMap::with_capacity(budgets);
        for _ in 0..budgets {
            // 根据分布进行随机抽取
            let chosen_index = weight_index.sample(rng);
            
            // 还原出 前缀区域 的下标
            let region_index = indexes[chosen_index];
            
            if let Some(c) = alloc.get_mut(&region_index) {
                // 如果之前存在, 分配数量加一
                *c += 1;
            } else { 
                alloc.insert(region_index, 1usize);
            }
        }
        
        alloc
    }
    

    fn init_pcs_list(path: &String, sample_pow: u64) -> Vec<PCSPlusTable> {
        let prefixes = TreeTraceIter::get_prefixes_from_file(path);

        let init_split_dot = 2u64.pow(sample_pow as u32);

        // 根据前缀信息生成初始 pcs列表
        let mut pcs_list = Vec::with_capacity(prefixes.len());
        for (cur_prefix, cur_prefix_len) in prefixes.into_iter() {
            pcs_list.push(
                PCSPlusTable {
                    // 前64位前缀
                    stub: cur_prefix,
                    // 地址生成掩码
                    mask: u64::MAX >> cur_prefix_len,

                    reward: 0,
                    offset: 0,

                    // 注意: 此处为实际生成的目标数量
                    gen_num: 0,
                    cur_gen_num: 0,
                    
                    // 初始化 汤姆森窗口
                    thompson_window: ThompsonWindow::new(),
                    
                    dest_info: Vec::new(),

                    sub_split_move_len: 64 - cur_prefix_len,
                    cur_sub_prefix_info: AHashMap::new(),

                    // 所有前缀的初始分割点均为
                    next_split_dot: init_split_dot,

                    // 所有前缀初始化为第一状态
                    pcs_state: PcsState::FIRST,

                    // 重复元素初始为空
                    repeat_targets: Vec::new(),
                    // 重复元素初始为空
                    repeat_tar_hashmap: AHashSet::new(),
                    not_finished: true,
                }
            )
        }

        pcs_list
    }
}