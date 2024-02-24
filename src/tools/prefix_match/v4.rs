use std::fs::File;
use std::io::{BufRead, BufReader};
use std::net::Ipv4Addr;
use std::process::exit;
use ahash::{AHashMap, AHashSet};
use log::error;
use crate::core::conf::tools::args_parse::u8::parse_u8_set;
use crate::SYS;
use crate::tools::file::parse_context::parse_line_with_annotation;
use crate::tools::others::sort::quick_sort_from_small_to_big;

#[allow(dead_code)]
pub struct Ipv4PrefixMatcher {

    // move_len = 32 - prefix_len
    // 右移距离 = 32 - 前缀长度
    right_move_len:Vec<u8>,

    // 保存的是 前缀值
    // 目标网段: [ prefix : others(subnet ip) ] => val: [ 0... : prefix ]
    // 每个右移距离 对应 一个map:  前缀值 -> asn号
    prefix_val:Vec<AHashMap<u32, u16>>,

    // 上述两个向量的 长度
    len:usize,

    // 默认粒度下的右移长度, 当 没有可以匹配的网段时使用 默认粒度
    // 默认右移长度 = 32 - 默认前缀粒度
    // 默认粒度下, 返回的 asn号码 为 0
    default_move_len:u8,

}


impl Ipv4PrefixMatcher {


    #[allow(dead_code)]
    pub fn new(path: String, default_granularity:u8, prefix_len_limit_str:&str) -> Self {

        let mut matcher = Self {
            right_move_len: vec![],
            prefix_val: vec![],
            len:0,
            default_move_len:32-default_granularity,
        };

        // 解析 限制前缀数组
        let prefix_len_limit = parse_u8_set(prefix_len_limit_str);

        // 从文件中加载
        matcher.from(path, &prefix_len_limit);

        // 按照网络前缀从大到小排序, 优化查找次序
        // 如 前缀 /24 /8 /16 的次序调整为 /24 /16 /8
        matcher.sort();

        matcher
    }


    fn from(&mut self, list_path:String, prefix_len_limit:&AHashSet<u8>) {

        let list_file = File::open(list_path.clone()).map_err(
            |_| {
                error!("{} {}", SYS.get_info("err", "open_targets_file_failed"), list_path);
                exit(1)
            }
        ).unwrap();

        let lines = BufReader::new(list_file).lines();

        for line in lines {

            match line {

                // 成功获取到该行
                Ok(l) => {

                    // 清除注释和无效行
                    match parse_line_with_annotation(l) {
                        Some(net_str) => {
                            self.parse_line_str(net_str, prefix_len_limit)
                        },
                        None => {}
                    }
                }
                Err(_) => {
                    error!("{} {}", SYS.get_info("err", "read_target_line_failed"), list_path);
                    exit(1)
                }
            }
        }
    }

    fn parse_line_str(&mut self, raw_net_str:String, prefix_len_limit:&AHashSet<u8>) {
        let mut net_mask_asn = raw_net_str.split("/");

        let net_str;
        let mask_str;
        let asn_str;
        if let Some(n) = net_mask_asn.next() {
            net_str = n;
        } else { 
            error!("{} {}", SYS.get_info("err","parse_line_err"), raw_net_str);
            exit(1)
        }

        if let Some(m_a) = net_mask_asn.next() {

            let mut net_mask_asn = m_a.split("\t");

            if let Some(m) = net_mask_asn.next() {
                mask_str = m;
            } else { 
                error!("{} {}", SYS.get_info("err","parse_line_err"), raw_net_str);
                exit(1)
            }

            if let Some(a) = net_mask_asn.next() {
                asn_str = a;
            } else { error!("{} {}", SYS.get_info("err","parse_line_err"), raw_net_str);
                exit(1)
            }

        } else { error!("{} {}", SYS.get_info("err","parse_line_err"), raw_net_str);
            exit(1)
        }


        let mask:u8 = mask_str.parse().map_err(|_|{
            error!("{} {}", SYS.get_info("err","parse_line_err"), raw_net_str);
            exit(1)
        }).unwrap();

        // 检查 掩码是否符合要求
        // 只有 存在于限制数组中的前缀长度才是有效的
        if !prefix_len_limit.contains(&mask) { return }

        let ip:Ipv4Addr = net_str.parse().map_err(|_|{
            error!("{} {}", SYS.get_info("err","parse_line_err"), raw_net_str);
            exit(1)
        }).unwrap();

        let asn:u16 = asn_str.parse().map_err(|_|{
            error!("{} {}", SYS.get_info("err","parse_line_err"), raw_net_str);
            exit(1)
        }).unwrap();

        // 添加网段
        self.add_net_from_ip_mask(ip, mask, asn);
    }

    fn add_net_from_ip_mask(&mut self,ip:Ipv4Addr, mask:u8, asn:u16){

        //  [  prefix(mask)  :   others (right_move_len)  ]
        let now_right_move_len = 32 - mask;

        //   [  prefix   :   others  ]   => [ 0... :   prefix  ]
        let ipu32 = u32::from(ip);
        let now_prefix_val = ipu32 >> now_right_move_len;

        let mut flag = true;
        for (index, len) in self.right_move_len.iter().enumerate() {

            // 如果存在对应长度, 将当前网段前缀值 加入 对应 hashset
            if *len == now_right_move_len {

                flag = false;
                self.prefix_val[index].insert(now_prefix_val, asn);
            }

        }

        if flag {
            // 如果没有 在已有前缀类型中 找到，就添加 类型 和 值
            self.right_move_len.push(now_right_move_len);

            // 相应添加 哈希表
            self.prefix_val.push(AHashMap::new());

            // 在当前最大下标上添加当前 前缀值
            self.prefix_val[self.len].insert(now_prefix_val, asn);

            // 更新当前的最大长度
            self.len += 1;
        }

    }

    /// 按照 网段大小 进行排序, 使得数据包先比较 前缀长度更大的网段, 再比较 前缀长度更小的网段
    fn sort(&mut self){

        // 如果长度为 0 就不需要排序
        if self.len == 0 {
            return
        }

        let right_index = self.len - 1;

        // 按照 右移大小 对 右移数量向量 和 前缀值向量 进行同步排序
        quick_sort_from_small_to_big(&mut self.right_move_len, &mut self.prefix_val, 0, right_index);
    }


    /// 获取 ip 对应的 最长前缀的  (右移长度, 前缀值, AS号码)
    #[allow(dead_code)]
    pub fn get_asn(&self, ip_val:u32) -> (u8, u32, u16) {

        for i in 0..self.len {

            let now_prefix_val = ip_val >> self.right_move_len[i];

            if self.prefix_val[i].contains_key(&now_prefix_val) {

                // 如果对应 map 类型已经包含 该ip 对应的前缀值
                // 说明 该ip 的对应网段 存在, 返回对应的 (右移长度, 前缀值, AS号码)
                return (self.right_move_len[i], now_prefix_val, *self.prefix_val[i].get(&now_prefix_val).unwrap())

            }

        }

        // 如果查询完所有的 前缀类型 后，依然没有符合的
        // 回复 (默认右移长度, 默认粒度下的前缀值, asn默认为0)
        (self.default_move_len, ip_val >> self.default_move_len, 0)
    }



}