use crate::modules::target_iterators::cycle_group::cycle_group::cycle_group_ipv4::CycleIpv4;
use crate::modules::target_iterators::Ipv4Iter;


impl CycleIpv4 {

    /// 以当前目标为基础, 计算并获取下一个目标
    /// 返回值: 是否为非最终值
    #[inline]
    fn get_next_target(&mut self) -> bool {

        loop {

            // (当前目标值 * 原根) % p
            self.current *= self.prim_root;
            self.current %= self.p;

            if self.current == self.last {
                // 如果当前乘法群的输出值为最终值, 标记为 false

                return false
            } else {

                // 使得 current 的值 始终处于  1..[    0..   |   tar_ip_num  ]
                // 注意这里 不等于0 的条件省略
                if self.current < self.valid_range {
                    return true
                }
            }
        }
    }
}


impl Ipv4Iter for CycleIpv4 {
    fn get_first_ip(&mut self) -> (bool, bool, u32) {
        if self.current == self.last {
            // 如果初始值是最后一个

            if self.current < self.valid_range {
                // ip值有效

                // ip值有效, 得到的 真实ip 也一定有效
                let real_ip = self.start_ip + ((self.current - 1) as u32);
                (false, true, real_ip)
            } else {
                // 如果 超出有效范围
                (false, false, 0)
            }
        } else {
            // 如果初始值不是最后一个

            if self.current < self.valid_range {
                // ip值有效

                // ip值有效, 得到的 真实ip 也一定有效
                let real_ip = self.start_ip + ((self.current - 1) as u32);
                (true, false, real_ip)
            } else {
                // ip值 超出有效范围
                self.get_next_ip()
            }
        }
    }

    fn get_next_ip(&mut self) -> (bool, bool, u32) {
        let target_ip_not_end = self.get_next_target();

        if target_ip_not_end {
            // 如果不是最终值

            // ip值有效, 得到的 真实ip 也一定有效
            let real_ip = self.start_ip + ((self.current - 1) as u32);

            (true, false, real_ip)
        } else {
            // 如果是最终值
            if self.current < self.valid_range {
                // 如果最终值有效

                // ip值有效, 得到的 真实ip 也一定有效
                let real_ip = self.start_ip + ((self.current - 1) as u32);
                (false, true, real_ip)
            } else {
                // 如果最终值无效
                (false, false, 0)
            }
        }
    }
}


