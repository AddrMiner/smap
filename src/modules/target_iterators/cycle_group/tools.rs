use std::process::exit;
use log::error;
use num_bigint::BigUint;
use num_traits::{FromPrimitive, ToPrimitive};
use crate::modules::target_iterators::cycle_group::cyclic::Cyclic;
use crate::SYS;

impl Cyclic {

    /// 确保目标值在 u64 表示范围内
    pub(crate) fn get_val_with_check_u64(val:u128) -> u64 {

        if val > (u64::MAX as u128) {
            error!("{}", SYS.get_info("err","p_too_big"));
            exit(1)
        }

        val as u64
    }

    /// 将 u64 解析为大数
    pub(crate) fn parse_u64_to_big_num(val:u64) -> BigUint {
        match BigUint::from_u64(val){
            Some(big_num) => big_num,
            None => {
                error!("{}", SYS.get_info("err","u64_to_big_num_err"));
                exit(1)
            }
        }
    }

    /// 将 大数 解析为 u64
    pub(crate) fn parse_big_num_to_u64(val:BigUint) -> u64 {
        match val.to_u64() {
            Some(f) => f,
            None => {
                error!("{}", SYS.get_info("err","big_num_to_u64_err"));
                exit(1)
            }
        }
    }


    /// 将 u128 解析为大数
    pub(crate) fn parse_u128_to_big_num(val:u128) -> BigUint {
        match BigUint::from_u128(val){
            Some(big_num) => big_num,
            None => {
                error!("{}", SYS.get_info("err","u128_to_big_num_err"));
                exit(1)
            }
        }
    }

    /// 将 大数 解析为 u128
    pub(crate) fn parse_big_num_to_u128(val:BigUint) -> u128 {
        match val.to_u128() {
            Some(f) => f,
            None => {
                error!("{}", SYS.get_info("err","big_num_to_u128_err"));
                exit(1)
            }
        }
    }


}