use std::process::exit;
use log::error;
use crate::SYS;

/// 将ipv6模式<u>二进制字符串</u>解析为, <u>ip所占的比特位总数(0)</u>, 将<u>模式字符位置换成0后的值(1)</u>, 掩码(2)(变动位为0,其它为1)
/// 和<u>片段信息(3)</u>, 最大ip  片段信息:  0: 片段长度 1: 片段相对最低位的偏移量
pub fn parse_ipv6_binary_pattern(pattern:&String) -> (u32, u128, u128, Vec<(u32, u32)>, u128) {

    // 将所有 模式位 变为 0 后的值
    let mut base_ip_val:u128 = 0;

    // 掩码, 如果为0或1,则该位为1; 如果为*,该位为0
    let mut mask:u128 = 0;

    // 获取所有模式字符的位置索引,索引范围为 [1, 128]
    let mut count = 0;
    let mut pattern_location:Vec<u32> = vec![];
    let pattern_chars = pattern.chars();
    for c in pattern_chars {
        match c {
            '0' => {
                count += 1;

                // 基础ip 当前位为0
                base_ip_val = base_ip_val << 1;

                // 掩码 当前位为1
                mask = mask << 1;
                mask += 1;
            }

            '1' => {
                count += 1;

                // 基础ip 当前位为1
                base_ip_val = base_ip_val << 1;
                base_ip_val += 1;

                // 掩码 当前位为1
                mask = mask << 1;
                mask += 1;
            }

            '*' => {
                count += 1;
                // 将当前位置(模式字符位置)加入位置向量
                pattern_location.push(count);

                // 基础ip 当前位为0
                base_ip_val = base_ip_val << 1;

                // 掩码  当前位为0
                mask = mask << 1;
            }
            // 忽略无效字符
            _  => {}
        }
    }

    if count != 128 {
        // 如果有效字符不等于128, 说明是无效字符串
        error!("{} {}", SYS.get_info("err", "parse_ipv6_binary_pattern_err"), pattern);
        exit(1)
    }


    let bits_for_ip = pattern_location.len() as u32;

    if bits_for_ip == 0 || bits_for_ip > 64 {
        error!("{}", SYS.get_info("err", "ipv6_pattern_bits_for_ip_invalid"));
        exit(1)
    }

    let end_ip_val = base_ip_val | (!mask);

    (bits_for_ip, base_ip_val, mask, get_parts_from_binary_locations(pattern_location), end_ip_val)

}

/// 从<u>二进制模式字符位置向量</u>获取<u>所有片段</u>的必要信息
/// 返回值:  Vec<(0, 1)>    0: 片段长度 1: 片段相对最低位的偏移量
fn get_parts_from_binary_locations(locations: Vec<u32>) -> Vec<(u32, u32)> {

    // 存放所有 连续片段 的 向量
    let mut location_parts = Vec::new();
    // 最后一个位置的索引
    let last_location = locations.len() - 1;
    // 每一个 连续位置片段 的内容
    let mut curr:Vec<u32> = Vec::new();


    for (index, cur_location) in locations.iter().enumerate() {

        // 取出 上一个位置
        let last = match curr.last() { Some(l) => Some(*l), None => None };

        match last {
            None => {}
            Some(l) => {
                // 如果存在上一个位置
                if  *cur_location > ( l + 1 ) {
                    // 如果不连续
                    location_parts.push(curr.clone());
                    curr.clear();
                } } }

        curr.push(*cur_location);

        // 如果是最后一次,并且当前保存值不为空
        if index == last_location && curr.len() != 0 {
            location_parts.push(curr.clone());
            curr.clear();
        }
    }

    let mut parts:Vec<(u32, u32)> = vec![];

    for part in location_parts {
        let last = part.last().unwrap();
        parts.push((part.len() as u32, 128 - last ));
    }

    parts
}