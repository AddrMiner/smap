use std::process::exit;
use log::{error, warn};
use crate::core::conf::tools::args_parse::port::parse_ports_vec;
use crate::SYS;

/// 定义目标迭代器基本配置
pub struct TarIterBaseConf {}


impl TarIterBaseConf {


    /// 解析 目标文件
    pub fn parse_targets_file(tar_file_str:&Option<String>) -> String {

        if let Some(t) = tar_file_str {
            t.to_string()
        } else {
            // 未设置 探测目标文件, 报错并提示用户输出
            error!("{}", SYS.get_info("err","targets_file_not_exist"));
            exit(1)
        }
    }



    /// 解析目标地址
    pub fn parse_tar_ip(tar_ip_str:&Option<String>) -> String {

        if let Some(t) = tar_ip_str {
            t.to_string()
        } else {
            // 未设置 目标地址, 报错并提示用户输出
            error!("{}", SYS.get_info("err","target_ips_not_exist"));
            exit(1)
        }
    }

    /// 解析目标端口
    pub fn parse_tar_port(tar_port_str:&Option<String>, default_tar_ports:&str) -> Vec<u16> {

        if let Some(t) = tar_port_str {
            parse_ports_vec(t)
        } else {
            // 未设置 目标端口, 提示警告后, 使用默认端口
            let tar_ports_str = SYS.get_info("conf", default_tar_ports);
            warn!("{} {}", SYS.get_info("warn","target_ports_not_exist"), tar_ports_str);
            parse_ports_vec(&tar_ports_str)
        }
    }

    /// 计算 ipv4 目标范围大小
    pub fn get_tar_ip_num_u32(first:u32, end:u32) -> u64 {
        (end - first + 1) as u64
    }


    /// 计算 ipv6 目标范围大小, 注意:ipv6的最大扫描范围不应超过 u64 所能表示的范围 (0..2^(64)-1)
    pub fn get_tar_ip_num_u128(first:u128, end:u128) -> u64 {
        let tar_num = end - first + 1;

        // 注意, ipv6的最大扫描范围不应超过 u64 所能表示的范围 (0..2^(64)-1)
        if tar_num > (u64::MAX as u128) {
            error!("{}", SYS.get_info("err","number_of_target_ipv6_addresses_out_of_range"));
            exit(1)
        }

        tar_num as u64
    }


    /// 通过<u>目标位置二进制位数</u>计算目标数量
    pub fn get_tar_ip_num_binary(bits_num:u32) -> u64 {

        let tar_num = 2u128.pow(bits_num);

        if tar_num > (u64::MAX as u128 + 1) {
            // 超过 2^64 的数量为非法
            error!("{}", SYS.get_info("err","number_of_target_ipv6_addresses_out_of_range"));
            exit(1)
        } else if tar_num == (u64::MAX as u128 + 1) {

            // 二进制循环群不对ip长度范围进行检查,且对速率控制器的影响几乎为0
            // 所以这里取近似值
            return u64::MAX
        }

        tar_num as u64
    }

    /// 使用乘法群的p-1和线程数量来进行目标分配, 注意返回向量的长度不一定和预设线程数量相等,这可能是因为有线程一个目标都分配不到.
    /// 注意应以此函数的长度作为实际执行的线程数量, 与预设线程数量不符合时, 以此函数的长度为准
    pub fn cycle_group_assign_targets_u128(p_sub_one:u128, thread_num:u128) -> Vec<(u128, u128, u64)> {

        let mut targets_ranges = vec![];

        let base_num = p_sub_one / thread_num;
        let mut remain_num = p_sub_one % thread_num;

        let mut pre_last = 0;
        for _ in 0..thread_num {

            let tar_num;
            if remain_num > 0 {
                tar_num = base_num + 1;
                remain_num -= 1;
            } else {
                tar_num = base_num;
            }

            if tar_num < 1 {
                return targets_ranges
            }

            let start = pre_last + 1;
            let end = start + tar_num - 1;

            targets_ranges.push((start, end, tar_num as u64));

            pre_last = end;
        }

        targets_ranges
    }

    /// 返回值: 0: 开始索引 1: 结束索引 2:范围数量
    /// 使用乘法群的p-1和线程数量来进行目标分配, 注意返回向量的长度不一定和预设线程数量相等,这可能是因为有线程一个目标都分配不到.
    /// 注意应以此函数的长度作为实际执行的线程数量, 与预设线程数量不符合时, 以此函数的长度为准
    pub fn cycle_group_assign_targets_u64(p_sub_one:u64, thread_num:u64) -> Vec<(u64, u64, u64)> {

        let mut targets_ranges = vec![];

        let base_num = p_sub_one / thread_num;
        let mut remain_num = p_sub_one % thread_num;

        let mut pre_last = 0;
        for _ in 0..thread_num {

            let tar_num;
            if remain_num > 0 {
                tar_num = base_num + 1;
                remain_num -= 1;
            } else {
                tar_num = base_num;
            }

            if tar_num < 1 {
                return targets_ranges
            }

            let start = pre_last + 1;
            let end = pre_last + tar_num;

            targets_ranges.push((start, end, tar_num));

            pre_last = end;
        }

        targets_ranges
    }


    /// 注意: 第一个参数是 起始索引减一
    pub fn cycle_group_assign_targets_u64_part(mut pre_last:u64, end_index:u64, thread_num:u64) -> Vec<(u64, u64, u64)> {

        let mut targets_ranges = vec![];

        let total_num = end_index - pre_last;

        let base_num = total_num / thread_num;
        let mut remain_num = total_num % thread_num;

        for _ in 0..thread_num {

            let tar_num;
            if remain_num > 0 {
                tar_num = base_num + 1;
                remain_num -= 1;
            } else {
                tar_num = base_num;
            }

            if tar_num < 1 {
                return targets_ranges
            }

            let start = pre_last + 1;
            let end = pre_last + tar_num;

            targets_ranges.push((start, end, tar_num));

            pre_last = end;
        }

        targets_ranges
    }

    /// 注意: 第一个参数是 起始索引减一
    pub fn cycle_group_assign_targets_u128_part(mut pre_last:u128, end_index:u128, range_num:u128) -> Vec<(u128, u128, u128)> {

        let mut targets_ranges = vec![];

        let total_num = end_index - pre_last;

        let base_num = total_num / range_num;
        let mut remain_num = total_num % range_num;

        for _ in 0..range_num {

            let tar_num;
            if remain_num > 0 {
                tar_num = base_num + 1;
                remain_num -= 1;
            } else {
                tar_num = base_num;
            }

            if tar_num < 1 {
                return targets_ranges
            }

            let start = pre_last + 1;
            let end = pre_last + tar_num;

            targets_ranges.push((start, end, tar_num));

            pre_last = end;
        }

        targets_ranges
    }



    pub fn cycle_group_assign_targets_mix(p_sub_one_vec_v4:Vec<u64>, p_sub_one_vec_v6:Vec<u128>,
                                            thread_num_v4:usize, thread_num_v6:usize,
        //  index: 线程下标    val: (start_index, end_index, tar_num)
                                            ) -> (Vec<Vec<(u64,u64,u64)>>, Vec<Vec<(u128,u128,u64)>>){

        let mut assigned_tasks_v4:Vec<Vec<(u64,u64,u64)>> = vec![vec![]; thread_num_v4];
        let mut assigned_tasks_v6:Vec<Vec<(u128,u128,u64)>> = vec![vec![]; thread_num_v6];

        for p_sub_one_v4 in p_sub_one_vec_v4 {
            // 对一个目标范围进行分解
            let assigned_target_range = TarIterBaseConf::cycle_group_assign_targets_u64(p_sub_one_v4, thread_num_v4 as u64);

            for i in 0..thread_num_v4 {
                if i < assigned_target_range.len() {
                    assigned_tasks_v4[i].push(assigned_target_range[i]);
                } else {
                    // 如果按线程数进行分解后不够每个线程一个元素, 长度标记为0
                    assigned_tasks_v4[i].push((0, 0, 0));
                }
            }
        }

        for p_sub_one_v6 in p_sub_one_vec_v6 {
            let assigned_target_range = TarIterBaseConf::cycle_group_assign_targets_u128(p_sub_one_v6, thread_num_v6 as u128);

            for i in 0..thread_num_v6 {
                if i < assigned_target_range.len() {
                    assigned_tasks_v6[i].push(assigned_target_range[i]);
                } else {
                    assigned_tasks_v6[i].push((0, 0, 0));
                }
            }
        }

        (assigned_tasks_v4, assigned_tasks_v6)
    }



    /// 返回值: 0:为ipv4分配的发送线程总数   1:为ipv6分配的发送线程总数
    pub fn assign_threads_for_v4_v6(total_p_sub_one_v4:u128, total_p_sub_one_v6:u128, send_thread_num:usize) -> (usize, usize) {

        if send_thread_num < 2 {
            error!("{}", SYS.get_info("err", "threads_num_less_than_two"));
            exit(1)
        }

        let send_thread_num_u128 = send_thread_num as u128;
        let total_p_sub_one = total_p_sub_one_v4 + total_p_sub_one_v6;

        let mid_v4 = total_p_sub_one_v4 * send_thread_num_u128;
        let mid_v6 = total_p_sub_one_v6 * send_thread_num_u128;
        let base_thread_num_v4 = mid_v4 / total_p_sub_one;
        let base_thread_num_v6 = mid_v6 / total_p_sub_one;

        let left_thread_num = send_thread_num_u128 - (base_thread_num_v4 + base_thread_num_v6);
        let (thread_num_v4, thread_num_v6) = if left_thread_num != 0 {
            if left_thread_num == 1 {
                // 如果剩余一个线程没分配, 将该线程分配给 剩余数量更多的一方
                let left_v4 = mid_v4 % total_p_sub_one;
                let left_v6 = mid_v6 % total_p_sub_one;

                if left_v4 > left_v6 {
                    ((base_thread_num_v4 + 1) as usize, base_thread_num_v6 as usize)
                } else {
                    (base_thread_num_v4 as usize, (base_thread_num_v6 + 1) as usize)
                }
            } else {
                // 因为 total_p_sub_one_v4 / (total_p_sub_one_v4 + total_p_sub_one_v6)
                //  +  total_p_sub_one_v6 / (total_p_sub_one_v4 + total_p_sub_one_v6)
                // 之和为 1, 如果一方出现小数, 则计算出的线程数 与 总线程数相差 1, 如果超出1表示出现异常
                error!("{}", SYS.get_info("err", "assign_threads_failed"));
                exit(1)
            }
        } else {
            (base_thread_num_v4 as usize, base_thread_num_v6 as usize)
        };

        if (thread_num_v4 + thread_num_v6) != send_thread_num {
            error!("{}", SYS.get_info("err", "assign_threads_failed"));
            exit(1)
        }

        if thread_num_v4 == 0 && total_p_sub_one_v4 != 0 {
            // 当存在 ipv4目标 时, 为ipv4分配的发送线程应至少为1
            (1, thread_num_v6 - 1)
        } else if thread_num_v6 == 0 && total_p_sub_one_v6 != 0 {
            // 当存在 ipv6目标 时, 为ipv6分配的发送线程应至少为1
            (thread_num_v4 - 1, 1)
        } else {
            (thread_num_v4, thread_num_v6)
        }
    }


    /// 计算<u>范围大小为n</u>所需要的位数
    pub fn bits_needed_usize(mut n:usize) -> u32 {

        // 如果只有1个也要占1位
        if n == 1 {
            return 1
        }

        n -= 1;
        let mut r = 0;

        while n!=0 {
            r+=1;
            n>>=1;
        }

        r
    }


    /// 计算<u>范围大小为n</u>所需要的位数
    pub fn bits_needed_u64(mut n:u64) -> u32 {

        // 如果只有1个也要占1位
        if n == 1 {
            return 1
        }

        n -= 1;
        let mut r = 0;

        while n!=0 {
            r+=1;
            n>>=1;
        }

        r
    }

}