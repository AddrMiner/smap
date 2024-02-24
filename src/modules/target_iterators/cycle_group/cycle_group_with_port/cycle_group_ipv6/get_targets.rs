use crate::modules::target_iterators::cycle_group::cycle_group_with_port::cycle_group_ipv6::CycleIpv6Port;
use crate::modules::target_iterators::Ipv6IterP;

impl CycleIpv6Port {

    /// 以当前目标为基础, 计算并获取下一个目标
    /// 返回值: 是否为非最终值
    #[inline]
    fn get_next_target(&mut self) -> bool {

        loop {

            // (当前目标值 * 原根) % p
            self.current *= self.prim_root;
            self.current %= self.p;

            if self.current == self.last {

                // 如果当前 乘法群的输出值为 最终值, 标记为 false
                return false
            } else {

                // 使得 current 的值 始终处于  1..[    0..   |   tar_ip_num - 1  |  1..   ]  + 1
                // 注意这里 不等于0 的条件省略
                if self.current < self.valid_range {
                    return true
                }

            }
        }
    }

    /// 输入: 乘法群输出  输出: 0:是否有效, true为有效  1: ip地址, 2: 端口号
    #[inline]
    fn parse_tar_val(&self, tar_val:u128) -> (bool, u128, u16) {

        // 乘法群的范围为 1 ... 2^(bits_num)
        // 地址的范围为 0 .. 2^(bits_num) - 1
        let target_val = tar_val - 1;

        // [ 0.. | ip | port ] => [ 0.. | port ]
        let port_val = ((target_val << self.port_move_len) >> self.port_move_len) as usize;

        // 如果 ip 值 小于 地址数量时才为合法, 比如地址数量为 8, ip值的范围应为 0..7 < 8
        // 由于 对ip值的限制包含在valid_range中, 所以这里可以不做检查
        if port_val < self.tar_port_num {

            //   [ 0.. | ip | port ]  => [ 0.. | ip ]
            let ip_val = target_val >> self.bits_for_port;

            // 注意 ip_val 的范围 0 .. < tar_ip_num , 其实是相对于起始地址的偏移量
            let real_ip = self.start_ip + ip_val;

            // 注意 port_val 的范围 0 .. < tar_port_num, 其实是 端口数组的下标
            let real_port = self.tar_ports[port_val];

            return (true, real_ip, real_port)
        }

        (false, 0 ,0)
    }


}


impl Ipv6IterP for CycleIpv6Port {
    fn get_first_ip_port(&mut self) -> (bool, bool, u128, u16) {
        if self.current == self.last {
            // 如果初始值是最后一个

            if self.current < self.valid_range {
                // 二进制范围有效
                let target = self.parse_tar_val(self.current);
                if target.0 {
                    // ip 和 port 有效
                    (false, true, target.1, target.2)
                } else {
                    // ip 和 port 无效
                    (false, false, 0, 0)
                }
            } else {
                // 如果 超出有效范围
                (false, false, 0, 0)
            }
        } else {
            // 如果初始值不是最后一个

            if self.current < self.valid_range {
                // 二进制范围有效
                let target = self.parse_tar_val(self.current);
                if target.0 {
                    // ip 和 port 有效
                    (true, false, target.1, target.2)
                } else {
                    // ip 和 port 无效
                    self.get_next_ip_port()
                }
            } else {
                // 如果 超出有效范围
                self.get_next_ip_port()
            }
        }
    }

    fn get_next_ip_port(&mut self) -> (bool, bool, u128, u16) {
        loop {
            let target_not_end = self.get_next_target();

            if target_not_end {
                // 如果不是最终值
                let target = self.parse_tar_val(self.current);

                if target.0 {
                    // 如果得到的 ip 和 port 有效
                    return (true, false, target.1, target.2)
                }

                // 如果 ip 和 port 无效, 循环直到得到 有效目标
            } else {
                // 如果是最终值
                return if self.current < self.valid_range {
                    // 如果最终值有效
                    let target = self.parse_tar_val(self.current);

                    if target.0 {
                        // 如果得到的 ip 和 port 有效
                        (false, true, target.1, target.2)
                    } else {
                        (false, false, 0, 0)
                    }
                } else {
                    // 如果最终值无效
                    (false, false, 0, 0)
                }
            }
        }
    }
}