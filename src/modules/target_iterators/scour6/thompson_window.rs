use std::collections::VecDeque;
use rand::distr::Distribution;
use rand::prelude::{ThreadRng};
use rand_distr::Beta;

#[derive(Clone)]
pub struct ThompsonWindow {
    // 历史数据
    // 注意: 每个历史数据由 (击中次数, 失败次数)
    pub history_record:VecDeque<(u32, u32)>,

    // 当前窗口下的成功数量
    pub window_success:u32,
    // 当前窗口下的失败数量
    pub window_failure:u32,
}


impl ThompsonWindow {
    pub fn new() -> Self {
        Self {
            history_record: VecDeque::new(),
            window_success: 0,
            window_failure: 0,
        }
    }
    
    pub fn clear(&mut self) {
        self.history_record.clear();
        self.history_record.shrink_to_fit();
    }

    pub fn update_window(&mut self, cur_success:u32, cur_failure:u32, window_size:u32) {
        // 先将数据加入记录(队尾)
        self.history_record.push_back((cur_success, cur_failure));
        self.window_success += cur_success;
        self.window_failure += cur_failure;

        loop {
            if let Some((front_success, front_failure)) = self.history_record.front() {
                // 如果 存在队首(非空)
                
                // 计算 队首(最老数据) 的总量
                let front_total = front_success + front_failure;
                
                if (self.get_total_num() - front_total) < window_size {
                    // 如果  当前总量 - 最老数据总量  小于 窗口大小
                    // 直接退出循环(不能删除该项)
                    // 也即 窗口总量必须始终大于等于窗口大小
                    
                    break;
                } else { 
                    // 如果 当前总量 - 最老数据 之后, 剩余的数据依然 大于等于窗口大小
                    
                    // 当前窗口成功总量 - 最老数据(超出窗口)
                    self.window_success -= front_success;
                    // 当前窗口失败总量 - 最老数据(超出窗口)
                    self.window_failure -= front_failure;
                    
                    // 弹出最老数据
                    self.history_record.pop_front();
                }
            } else { 
                // 如果所有数据已经为空
                break;
            }
        }
    }
    
    #[inline]
    fn get_total_num(&self) -> u32 {
        self.window_success + self.window_failure
    }


    /// 获取 汤姆森采样值
    pub fn get_weight(&self, rng: &mut ThreadRng) -> f64 {
        let success = (self.window_success as f64) + 1.0;
        let failure = (self.window_failure as f64) + 1.0;

        Beta::new(success, failure).unwrap().sample(rng)
    }
}