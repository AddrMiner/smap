use crate::modules::target_iterators::{Ipv6Iter, Topo6Iter};
use crate::modules::target_iterators::topo::v6::topo_iter_v6::TopoIterV6;

impl Topo6Iter for TopoIterV6 {
    fn get_first_ip_ttl(&mut self) -> (bool, bool, u128, u8) {

        if self.current == self.last {
            // 如果初始值是最后一个

            if self.current < self.valid_range {
                // index 有效
                let index = (self.current - 1) as usize;
                // 使用索引 取出该地址对应的 状态
                //     [ 地址1                              , 地址2, ...  ]
                //     [ u8(  下一个ttl | 是否接收到响应(1比特)), u8, ....   ]
                // 注意: 已接收响应为1, 未接收响应为0
                let code = self.state_chain[index];

                // 如果 code 等于 0, 表示 不为探测目标(根据预扫描结果并未选中) 或 目标已经完成探测
                if code != 0 {
                    // 注意: 这里将 局部索引 转换为 全局索引
                    let real_ip = self.get_real_ip_from_tar_val((index + self.start_index) as u128);
                    (false, true, real_ip, code >> 1)
                } else {
                    (false, false, 0, 0)
                }
            } else {
                // 如果 超出有效范围
                (false, false, 0, 0)
            }
        } else {
            // 如果初始值不是最后一个

            if self.current < self.valid_range {
                // index 有效

                let index = (self.current - 1) as usize;
                // 使用索引 取出该地址对应的 状态
                //     [ 地址1                              , 地址2, ...  ]
                //     [ u8(  下一个ttl | 是否接收到响应(1比特)), u8, ....   ]
                // 注意: 已接收响应为1, 未接收响应为0
                let code = self.state_chain[index];

                // 如果 code 等于 0, 表示 不为探测目标(根据预扫描结果并未选中) 或 目标已经完成探测
                if code != 0 {
                    // 注意: 这里将 局部索引 转换为 全局索引
                    let real_ip = self.get_real_ip_from_tar_val((index + self.start_index) as u128);
                    return (true, false, real_ip, code >> 1)
                } else {
                    // 当前ip不在探测范围
                    // 继续寻找下一个目标
                    self.get_next_ip_ttl()
                }
            } else {
                // index 超出有效范围
                self.get_next_ip_ttl()
            }
        }
    }

    fn get_next_ip_ttl(&mut self) -> (bool, bool, u128, u8) {

        loop {
            let target_not_end = self.get_next_target();

            if target_not_end {
                // 如果不是最终值

                let index = (self.current - 1) as usize;
                // 使用索引 取出该地址对应的 状态
                //     [ 地址1                              , 地址2, ...  ]
                //     [ u8(  下一个ttl | 是否接收到响应(1比特)), u8, ....   ]
                // 注意: 已接收响应为1, 未接收响应为0
                let code = self.state_chain[index];

                // 如果 code 等于 0, 表示 不为探测目标(根据预扫描结果并未选中) 或 目标已经完成探测
                if code != 0 {
                    // 注意: 这里将 局部索引 转换为 全局索引
                    let real_ip = self.get_real_ip_from_tar_val((index + self.start_index) as u128);
                    return (true, false, real_ip, code >> 1)
                }

                // 如果 ip 和 ttl 无效, 循环直到得到 有效目标
            } else {
                // 如果是最终值
                return if self.current < self.valid_range {
                    // 如果最终值有效
                    let index = (self.current - 1) as usize;
                    // 使用索引 取出该地址对应的 状态
                    //     [ 地址1                              , 地址2, ...  ]
                    //     [ u8(  下一个ttl | 是否接收到响应(1比特)), u8, ....   ]
                    // 注意: 已接收响应为1, 未接收响应为0
                    let code = self.state_chain[index];

                    // 如果 code 等于 0, 表示 不为探测目标(根据预扫描结果并未选中) 或 目标已经完成探测
                    return if code != 0 {
                        // 注意: 这里将 局部索引 转换为 全局索引
                        let real_ip = self.get_real_ip_from_tar_val((index + self.start_index) as u128);
                        (false, true, real_ip, code >> 1)
                    } else {
                        // 当前ip不在探测范围
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


impl TopoIterV6 {

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
    #[inline]
    fn get_real_ip_from_tar_val(&self, ip_val: u128) -> u128 {
        // [  0..  ( 位数 : 128 - bits_for_ip)  |    part1 ( 位数: parts.0 )   |   part2 ( 位数: parts.0 )  |  part3 ( 位数: parts.0 ) ]
        // =>
        // 清除前置比特位
        // [ part1 |   0..    (128 - parts.0)      ]
        // [ part2 |   0..    (128 - parts.0)      ]
        // [ part3 |   0..    (128 - parts.0)      ]
        // =>
        // 清除后置比特位
        // [ 0..  | part1 ]
        // [ 0..  | part2 ]
        // [ 0..  | part3 ]
        // =>
        // 使用偏移量进行调整
        // [ part1  |       0..   ( 位数: parts.1 )                   ]
        // [    0..         |  part2 |     0..  ( 位数: parts.1 )     ]
        // [    0..                         |  part3 ]      // ( 位数: parts.1  为 0 )
        // =>
        // 所有片段 或运算
        // [  part1 |  0..  |  part2 |  0.. |  part3 ]


        // 对所有ip片段进行 或运算
        let mut real_ip = self.base_ip_val;
        for part_move in self.ip_move_len.iter() {
            // (0: 第一次左移位数, 1: 右移位数, 2: 第二次左移位数)

            let cur_part =
                ((ip_val << part_move.0) >> part_move.1) << part_move.2;
            real_ip = real_ip | cur_part;
        }

        real_ip
    }
}

// 辅助预扫描迭代器
impl Ipv6Iter for TopoIterV6 {
    fn get_first_ip(&mut self) -> (bool, bool, u128) {
        if self.current == self.last {
            // 如果初始值是最后一个

            if self.current < self.valid_range {
                // index 有效
                let index = (self.current - 1) as usize;
                // 使用索引 取出该地址对应的 状态
                //     [ 地址1                              , 地址2, ...  ]
                //     [ u8(  下一个ttl | 是否接收到响应(1比特)), u8, ....   ]
                // 注意: 已接收响应为1, 未接收响应为0
                let code = self.state_chain[index];

                // 如果 code 等于 0, 表示 为首次预扫描未响应的目标
                if code == 0 {
                    // 注意: 这里将 局部索引 转换为 全局索引
                    let real_ip = self.get_real_ip_from_tar_val((index + self.start_index) as u128);
                    (false, true, real_ip)
                } else {
                    (false, false, 0)
                }
            } else {
                // 如果 超出有效范围
                (false, false, 0)
            }
        } else {
            // 如果初始值不是最后一个

            if self.current < self.valid_range {
                // index 有效

                let index = (self.current - 1) as usize;
                // 使用索引 取出该地址对应的 状态
                //     [ 地址1                              , 地址2, ...  ]
                //     [ u8(  下一个ttl | 是否接收到响应(1比特)), u8, ....   ]
                // 注意: 已接收响应为1, 未接收响应为0
                let code = self.state_chain[index];

                // 如果 code 等于 0, 表示 为首次预扫描未响应的目标
                if code == 0 {
                    // 注意: 这里将 局部索引 转换为 全局索引
                    let real_ip = self.get_real_ip_from_tar_val((index + self.start_index) as u128);
                    return (true, false, real_ip)
                } else {
                    // 当前ip不在探测范围
                    // 继续寻找下一个目标
                    self.get_next_ip()
                }
            } else {
                // index 超出有效范围
                self.get_next_ip()
            }
        }
    }

    fn get_next_ip(&mut self) -> (bool, bool, u128) {
        loop {
            let target_not_end = self.get_next_target();

            if target_not_end {
                // 如果不是最终值

                let index = (self.current - 1) as usize;
                // 使用索引 取出该地址对应的 状态
                //     [ 地址1                              , 地址2, ...  ]
                //     [ u8(  下一个ttl | 是否接收到响应(1比特)), u8, ....   ]
                // 注意: 已接收响应为1, 未接收响应为0
                let code = self.state_chain[index];

                // 如果 code 等于 0, 表示 为首次预扫描未响应的目标
                if code == 0 {
                    // 注意: 这里将 局部索引 转换为 全局索引
                    let real_ip = self.get_real_ip_from_tar_val((index + self.start_index) as u128);
                    return (true, false, real_ip)
                }

                // 如果 目标 无效, 循环直到得到 有效目标
            } else {
                // 如果是最终值
                return if self.current < self.valid_range {
                    // 如果最终值有效
                    let index = (self.current - 1) as usize;
                    // 使用索引 取出该地址对应的 状态
                    //     [ 地址1                              , 地址2, ...  ]
                    //     [ u8(  下一个ttl | 是否接收到响应(1比特)), u8, ....   ]
                    // 注意: 已接收响应为1, 未接收响应为0
                    let code = self.state_chain[index];

                    // 如果 code 等于 0, 表示 为首次预扫描未响应的目标
                    return if code == 0 {
                        // 注意: 这里将 局部索引 转换为 全局索引
                        let real_ip = self.get_real_ip_from_tar_val((index + self.start_index) as u128);
                        (false, true, real_ip)
                    } else {
                        // 当前ip不在探测范围
                        (false, false, 0)
                    }
                } else {
                    // 如果最终值无效
                    (false, false, 0)
                }
            }
        }
    }
}