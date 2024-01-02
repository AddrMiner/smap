use ahash::AHashMap;
use crate::tools::others::sort::quick_sort_from_big_to_small;


pub struct Graph {

    // 当前概率相关图的地址总量
    pub ip_cnt:usize,

    // 当前概率相关图的端口总量
    pub port_cnt:usize,

    //  端口号 -> 该端口的总计数
    pub single_cnt: AHashMap<u16, u64>,

    // 端口 -> 相关端口 -> (端口 -> 相关端口)的计数
    pub both_cnt:AHashMap<u16,AHashMap<u16, u64>>,

    // 绝对概率表   以下三个列表相同下标分别对应 同一个端口的 端口号, 总计数, 绝对概率
    // 端口列表(按 端口对应的总计数值 从大到小排序)
    pub recommend_ports:Vec<u16>,
    // 端口计数列表(按 端口对应的总计数值 从大到小排序)
    pub recommend_ports_cnt:Vec<u64>,
    // 端口绝对概率列表(按 端口对应的总计数值 从大到小排序)
    pub recommend_ports_probability:Vec<f64>,

    // 端口(下标) -> 端口对应的绝对概率(值)
    pub port_to_ab_probability:Box<[f64;65536]>,

    // 目标端口向量
    pub tar_ports:Vec<u16>,
    // 目标端口长度
    pub tar_ports_len:usize,
}


impl Graph {

    pub fn new(mut tar_ports:Vec<u16>) -> Self {

        tar_ports.sort();
        let sorted_tar_ports = Self::sort_tar_ports(tar_ports);
        let tar_ports_len = sorted_tar_ports.len();

        Self {
            ip_cnt: 0,
            port_cnt: 0,

            // 检查时注意修改 容量, 这里的容量必须大于1
            single_cnt: AHashMap::with_capacity(1024),
            both_cnt: AHashMap::with_capacity(1024),

            recommend_ports: vec![],
            recommend_ports_cnt: vec![],
            recommend_ports_probability: vec![],

            port_to_ab_probability: Box::new([0.0; 65536]),

            tar_ports:sorted_tar_ports,
            tar_ports_len,
        }

    }

    pub fn new_void() -> Self {

        Self {
            ip_cnt: 0,
            port_cnt: 0,
            single_cnt: AHashMap::with_capacity(0),
            both_cnt: AHashMap::with_capacity(0),
            recommend_ports: vec![],
            recommend_ports_cnt: vec![],
            recommend_ports_probability: vec![],
            port_to_ab_probability: Box::new([0.0; 65536]),
            tar_ports: vec![],
            tar_ports_len: 0,
        }
    }



    /// 将同一个ip的全部探活端口作为输入, 训练概率相关图
    pub fn update_from_ip(&mut self, active_ports:&Vec<u16>) {

        self.ip_cnt += 1;

        // 取得当前ip活跃端口的数量
        let active_ports_len = active_ports.len();
        if active_ports_len == 0 {
            return
        }

        let active_ports_len_sub = active_ports_len - 1;

        // cur_index: 0 .. len-2
        for cur_index in 0..active_ports_len_sub {

            // 当前活跃端口
            let cur_active_port = active_ports[cur_index];

            // 端口 -> 该端口的总计数
            // 为 当前端口 增加计数, 注意这里没有增加 最后一个元素 的计数值
            if let Some(cur_sin) = self.single_cnt.get_mut(&cur_active_port) {
                // 如果原本存在, 在原来的值的基础上加一
                *cur_sin += 1;
            } else {
                // 如果原本不存在, 创建该关系, 并直接计数为1
                self.single_cnt.insert(cur_active_port, 1);
            }

            //  next_index: cur_index+1 .. len-1
            let second_index = cur_index + 1;
            for next_index in second_index..active_ports_len {

                // 与当前活跃端口相关的 活跃端口
                let next_active_port = active_ports[next_index];

                // 当前端口 -> 关系端口 -> 关系计数
                match self.both_cnt.get_mut(&cur_active_port) {
                    Some(cur_ptr) => {
                        // 如果 当前活跃端口 存在

                        if let Some(next_ptr) = cur_ptr.get_mut(&next_active_port) {
                            // 如果存在对应关系端口, 增加 计数值
                            *next_ptr += 1;
                        } else {
                            // 如果不存在对应关系端口, 添加对应关系端口, 并直接将计数值设为 1
                            cur_ptr.insert(next_active_port, 1);
                        }
                    }
                    None => {
                        // 如果 当前活跃端口 不存在

                        // 创建 内层 关系端口 -> 关系计数 的映射
                        let mut next_to_num: AHashMap<u16, u64> = AHashMap::new();
                        next_to_num.insert(next_active_port, 1);

                        self.both_cnt.insert(cur_active_port, next_to_num);
                    }
                }

                // 关系端口 -> 当前端口 -> 关系计数
                match self.both_cnt.get_mut(&next_active_port) {
                    Some(next_ptr) => {
                        // 如果 关系端口 存在

                        if let Some(cur_ptr) = next_ptr.get_mut(&cur_active_port) {
                            // 如果存在 当前端口, 增加 计数值
                            *cur_ptr += 1;
                        } else {
                            // 如果不存在 当前端口, 添加当前端口, 并直接将计数值设为1
                            next_ptr.insert(cur_active_port, 1);
                        }
                    }
                    None => {
                        // 如果 关系端口 不存在

                        // 创建内层 当前端口 -> 关系计数 的映射
                        let mut cur_to_num: AHashMap<u16, u64> = AHashMap::new();
                        cur_to_num.insert(cur_active_port, 1);

                        self.both_cnt.insert(next_active_port, cur_to_num);
                    }
                }
            }
        }

        // 为 最后一个元素 增加计数
        let cur_active_port = active_ports[active_ports_len_sub];
        if let Some(cur_sin) = self.single_cnt.get_mut(&cur_active_port) {
            // 如果原本存在, 在原来的值的基础上加一
            *cur_sin += 1;
        } else {
            // 如果原本不存在, 创建该关系, 并直接计数为1
            self.single_cnt.insert(cur_active_port, 1);
        }
    }


    /// 在进行一次完整的训练后, 必须调用此函数, 生成绝对概率表
    pub fn update_end(&mut self) {

        self.port_cnt = self.single_cnt.len();
        if self.port_cnt == 0 { return }

        self.recommend_ports = Vec::with_capacity(self.port_cnt);
        self.recommend_ports_cnt = Vec::with_capacity(self.port_cnt);
        self.recommend_ports_probability = Vec::with_capacity(self.port_cnt);

        for (port, port_single_cnt) in self.single_cnt.iter() {
            self.recommend_ports.push(*port);
            self.recommend_ports_cnt.push(*port_single_cnt);
        }

        quick_sort_from_big_to_small(&mut self.recommend_ports_cnt, &mut self.recommend_ports, 0, self.port_cnt-1);

        self.port_to_ab_probability = Box::new([0.0; 65536]);

        let ip_cnt_f64 = self.ip_cnt as f64;
        for i in 0..self.port_cnt {

            let cur_pro = (self.recommend_ports_cnt[i] as f64) / ip_cnt_f64;
            self.recommend_ports_probability.push(cur_pro);

            // 索引: 端口      值: 该端口对应的绝对概率值
            self.port_to_ab_probability[self.recommend_ports[i] as usize] = cur_pro;
        }
    }
}