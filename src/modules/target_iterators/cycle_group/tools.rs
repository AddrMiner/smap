use std::process::exit;
use log::error;
use num_bigint::BigUint;
use num_traits::{FromPrimitive, ToPrimitive};
use crate::modules::target_iterators::cycle_group::cyclic::Cyclic;
use crate::SYS;

impl Cyclic {

    /// 确保目标值在 u64 表示范围内
    pub fn get_val_with_check_u64(val:u128) -> u64 {

        if val > (u64::MAX as u128) {
            error!("{}", SYS.get_info("err","p_too_big"));
            exit(1)
        }

        val as u64
    }

    /// 将 u64 解析为大数
    pub fn parse_u64_to_big_num(val:u64) -> BigUint {
        BigUint::from_u64(val).unwrap_or_else(|| {
            error!("{}", SYS.get_info("err","u64_to_big_num_err"));
            exit(1)
        })
    }

    /// 将 大数 解析为 u64
    pub fn parse_big_num_to_u64(val:BigUint) -> u64 {
        val.to_u64().unwrap_or_else(|| {
            error!("{}", SYS.get_info("err","big_num_to_u64_err"));
            exit(1)
        })
    }


    /// 将 u128 解析为大数
    pub fn parse_u128_to_big_num(val:u128) -> BigUint {
        BigUint::from_u128(val).unwrap_or_else(|| {
            error!("{}", SYS.get_info("err","u128_to_big_num_err"));
            exit(1)
        })
    }

    /// 将 大数 解析为 u128
    pub fn parse_big_num_to_u128(val:BigUint) -> u128 {
        val.to_u128().unwrap_or_else(|| {
            error!("{}", SYS.get_info("err","big_num_to_u128_err"));
            exit(1)
        })
    }


    /// 获取片段移动位数
    /// 返回值: (0: 第一次左移位数, 1: 右移位数, 2: 第二次左移位数)
    pub fn get_move_len(bits_for_ip:u32, bits_for_payload:u32, parts:Vec<(u32, u32)>, total_bits_len:u32) -> Vec<(u32, u32, u32)> {

        // [  0..  ( 位数 : total_bits_len(32/128) - bits_for_ip - bits_for_payload)  |    part1 ( 位数: parts.0 )   |   part2 ( 位数: parts.0 )  |  part3 ( 位数: parts.0 )  |  payload  ]
        // =>
        // 清除前置比特位
        // [ part1 |   0..    (total_bits_len - parts.0)      ]
        // [ part2 |   0..    (total_bits_len - parts.0)      ]
        // [ part3 |   0..    (total_bits_len - parts.0)      ]
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


        // 0: 第一次左移位数    1: 右移位数  2: 第二次左移位数
        let mut move_len:Vec<(u32, u32, u32)> = vec![];

        let leading_zeros = total_bits_len - bits_for_ip - bits_for_payload;

        let mut left_move = leading_zeros;
        for part in parts {

            move_len.push((left_move, total_bits_len - part.0, part.1));
            left_move += part.0;
        }

        move_len
    }


}