use std::fs::File;
use std::io::{BufRead, BufReader};
use std::net::Ipv4Addr;
use std::process::exit;
use std::str::FromStr;
use ahash::AHashSet;
use log::error;
use crate::SYS;
use crate::DNS;
use crate::tools::file::parse_context::parse_line_with_annotation;
use crate::tools::others::sort::quick_sort_from_big_to_small;

/// ipv4 黑名单 或 白名单 生成器
pub struct Ipv4Blocker {
    // move_len = 32 - prefix_len
    // 右移距离 = 32 - 前缀长度
    right_move_len:Vec<u32>,

    // 保存的是 前缀值
    // 目标网段: [ prefix : others(subnet ip) ] => val: [ 0... : prefix ]
    // 每个右移距离 对应 一个前缀值set
    prefix_val:Vec<AHashSet<u32>>,

    // 上述两个向量的 长度
    len:usize,

    // ipv4 全域 标记
    mark_all_flag:bool,
}

impl Clone for Ipv4Blocker {
    fn clone(&self) -> Self {
        Self {
            right_move_len: self.right_move_len.clone(),
            prefix_val: self.prefix_val.clone(),
            len: self.len,
            mark_all_flag: self.mark_all_flag,
        }
    }

}


impl Ipv4Blocker {

    /// 黑名单 or 白名单 拦截器初始化
    pub fn new(path: String) -> Self {

        let mut blocker = Ipv4Blocker::void();

        // 从文件中加载
        blocker.from(path);

        // 按照网络前缀从小到大排序, 优化查找次序
        // 如 前缀 /24 /8 /16 的次序调整为 /8 /16 /24
        blocker.sort();

        // 前缀聚合必须在排序之后
        blocker.aggregation_prefix();

        blocker
    }

    /// 生成 空拦截器, 默认禁用全域标记
    pub fn void() -> Self {

        Self {
            right_move_len: vec![],
            prefix_val: vec![],
            len:0,

            // 默认禁用全域标记
            mark_all_flag:false,
        }

    }

    /// 清空约束, 并选择是否标记全域
    pub fn clear(&mut self, mark_all:bool) {

        // 全域标记
        self.mark_all_flag = mark_all;

        // 清空右移长度向量, 释放空间, 并初始化
        self.right_move_len.clear();
        self.right_move_len.shrink_to_fit();
        self.right_move_len = vec![];

        // 清空前缀值向量, 释放空间, 并初始化
        self.prefix_val.clear();
        self.prefix_val.shrink_to_fit();
        self.prefix_val = vec![];


        // 向量长度重置
        self.len = 0;

    }

    /// 从文件路径生成 拦截器
    fn from(&mut self, list_path:String) {

        let list_file = File::open(list_path).map_err(
            |_| {
                error!("{}", SYS.get_info("err", "open_black_white_list_file_err"));
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

                            // 如果出现全域标记, 添加后续网段是 完全不需要 的,而且会导致匹配开销
                            if self.mark_all_flag {
                                return
                            }

                            self.parse_line_str(net_str)
                        },

                        None => {}
                    }

                }
                Err(_) => {
                    error!("{}", SYS.get_info("err", "read_black_white_list_file_err"));
                    exit(1)
                }
            }
        }
    }


    /// 从 行字符串文本 解析, 一次只能添加一个 网段 or 域名(多个地址) or ip地址
    fn parse_line_str(&mut self, raw_net_str:String){

        let mut net_mask = raw_net_str.split("/");

        let net_str;
        let mask_str;
        if let Some(n) = net_mask.next() {
            net_str = n;
        } else {
            error!("{} {}", SYS.get_info("err","parse_line_err"), raw_net_str);
            exit(1)
        }

        if let Some(m) = net_mask.next() {
            mask_str = m;
        } else {

            // 如果无法获取到 前缀长度
            match Ipv4Addr::from_str(net_str) {

                Ok(ip) => { // 成功解析为 ipv4地址
                    self.add_net_from_ip_mask(ip, 32);
                    return
                }
                Err(_) => {
                    // 尝试当作 域名 来解析
                    match DNS.domain_to_v4(net_str) {
                        Ok(ips) => {
                            // 得到域名对应的地址序列

                            for ip in ips {
                                // 对解析出的所有地址进行标记
                                self.add_net_from_ip_mask(ip, 32);
                            }

                            return
                        }
                        Err(_) => {
                            // 如果既不是 ip 地址, 也不是域名, 就直接报错
                            error!("{} {}", SYS.get_info("err","parse_line_err"), raw_net_str);
                            exit(1)
                        }
                    }
                }
            }
        }

        if let Some(_) = net_mask.next() {      // 检查合法性
            error!("{} {}", SYS.get_info("err","parse_line_err"), raw_net_str);
            exit(1)
        }

        let ip:Ipv4Addr = net_str.parse().map_err(|_|{
            error!("{} {}", SYS.get_info("err","parse_line_err"), raw_net_str);
            exit(1)
        }).unwrap();
        let mask:u32 = mask_str.parse().map_err(|_|{
            error!("{} {}", SYS.get_info("err","parse_line_err"), raw_net_str);
            exit(1)
        }).unwrap();

        // 添加网段
        self.add_net_from_ip_mask(ip, mask);
    }

    /// 使用 ip 和 mask, 添加网络
    fn add_net_from_ip_mask(&mut self,ip:Ipv4Addr, mask:u32){

        if mask > 32 {

            // mask 超过 32 位为非法 mask
            error!("{} {}/{}", SYS.get_info("err","parse_line_err"), ip, mask);
            exit(1)
        }

        if mask == 0 {
            // mask 为 0 时, 表示标记所有地址
            if ip != Ipv4Addr::new(0,0,0,0) {

                // 非法全域标记
                error!("{} {}/{}", SYS.get_info("err","illegal_all_flag"), ip, mask);
                exit(1)
            }

            // 清空各向量, 并添加 全域标记
            self.clear(true);
            return
        }


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
                self.prefix_val[index].insert(now_prefix_val);
            }

        }

        if flag {
            // 如果没有 在已有前缀类型中 找到，就添加 类型 和 值
            self.right_move_len.push(now_right_move_len);

            // 相应添加 哈希表
            self.prefix_val.push(AHashSet::new());

            // 在当前最大下标上添加当前 前缀值
            self.prefix_val[self.len].insert(now_prefix_val);

            // 更新当前的最大长度
            self.len += 1;
        }

    }

    /// 按照 网段大小 进行排序, 使得数据包先比较 大的网段, 再比较 小的网段
    fn sort(&mut self){

        // 如果长度为 0 就不需要排序
        if self.len == 0 {
            return
        }

        let right_index = self.len - 1;

        // 按照 右移大小 对 右移数量向量 和 前缀值向量 进行同步排序
        quick_sort_from_big_to_small(&mut self.right_move_len, &mut self.prefix_val, 0, right_index);
    }


    /// 前缀聚合
    /// 删除 较大网络 中包含的 较小网络
    fn aggregation_prefix(&mut self){

        if self.len == 0 {
            return
        }

        let mut new_right_move:Vec<u32> = vec![];
        let mut new_prefix_val:Vec<AHashSet<u32>> = vec![];

        // 按照 右移位数 对所有限制子网的 类型 进行遍历, 先遍历到的是 右移位数更多 , 也就是 前缀长度更少的
        for (index, right_move_len) in self.right_move_len.iter().enumerate() {

            // 取出 当前网段类型(按前缀长度划分) 的 右移距离
            let now_right_len = *right_move_len;

            // 如果不是 最大的 子网
            if index != 0 {

                // 当前网段类型下, 不被 更大网段 包含的 网段集合
                let mut prefix_val_set = AHashSet::new();

                // 遍历当前 前缀长度类型 中的全部子网
                // 遍历值 为 原始前缀值
                for raw_prefix_val in self.prefix_val[index].iter() {

                    // 标记 当前子网 是否 不被包含
                    let mut is_not_included = true;

                    // 针对 当前前缀长度 中的 特定子网, 对 比它前缀长度更小 的所有子网进行遍历查询
                    for smaller_prefix_index in (0..index).rev() {

                        // 原始前缀值 => 当前 前缀长度 下的 前缀值
                        let now_val = (*raw_prefix_val) >>
                            (&self.right_move_len[smaller_prefix_index] - now_right_len);

                        // 如果 前缀更小 的 网段 中 包含 当前网段
                        if self.prefix_val[smaller_prefix_index].contains(&now_val) {
                            // 更小前缀网段 中 包含 该网段, 意味着 该网段 是多余的
                            // 因为匹配到 包含着它的更大网段 时, 就没必要进一步匹配 粒度更小的网段

                            // 该 前缀更大的小网段 被删除后, 就没必要继续和 其他更小前缀的 网段进行比较

                            is_not_included = false;
                            break
                        }
                    }
                    // 如果该 网段 不被 任何更大的网段 包含
                    if is_not_included {
                        prefix_val_set.insert(*raw_prefix_val);
                    }
                }

                // 如果该 类型网段 存在 约束网段
                if prefix_val_set.len() != 0 {
                    new_right_move.push(now_right_len);
                    new_prefix_val.push(prefix_val_set);
                }
            } else {
                // 最短前缀的网段直接添加
                new_right_move.push(now_right_len);
                new_prefix_val.push(self.prefix_val[0].clone());
            }
        }

        // 清空 原有的所有数据, 注意不要标记全域
        self.clear(false);

        // 用整理之后的值进行替代
        self.len = new_right_move.len();
        self.right_move_len = new_right_move;
        self.prefix_val = new_prefix_val;

    }



    /// 范围筛选
    /// 根据输入的探测范围来减少约束项
    /// 具体方法为:
    /// 根据 开始 和 结束 的 最长共有前缀 计算 目标范围子网
    /// 如果 目标范围子网 整个包含在已有的标记范围内, 直接返回 全部标记 信息
    /// 如果 目标范围子网 与 已有标记范围无关, 右移长度和前缀值列表应为 空
    /// 如果 目标范围子网 中 包含 一个或者多个 已有标记范围, 右移长度和前缀值列表应只保留 目标范围子网 内的约束
    pub fn set_tar_range(&self, start:u32, end:u32) -> Self {

        if self.len == 0 {
            return Self {
                right_move_len: vec![],
                prefix_val: vec![],
                len: 0,
                mark_all_flag: self.mark_all_flag,
            }
        }

        // 获得 共同前缀 和 共同前缀长度
        let (common_prefix_val, tar_right_len) = common_prefix(
            start, end
        );

        if tar_right_len == 32 {
            // 如果 右移距离为 32, 即共同前缀前缀长度为 0
            // 共同前缀为0, 也就意味着 目标涵盖所有子网
            // 所有约束都对 目标范围 生效

            return (*self).clone()
        }

        let mut constraint_prefix_val:Vec<AHashSet<u32>> = vec![];
        let mut constraint_right_move_len:Vec<u32> = vec![];

        for (index, right_move_len) in self.right_move_len.iter().enumerate() {

            let now_right_move_len = *right_move_len;

            if now_right_move_len >= tar_right_len {
                // 如果 比较网段 比 目标网段 更大或同等规模

                // 计算 目标网段 在 比较网段 中的前缀值
                let now_val = common_prefix_val >> (now_right_move_len - tar_right_len);

                if self.prefix_val[index].contains(&now_val) {
                    // 如果 现有约束 完全包含该网段
                    // 返回 全部标记
                    return Self {
                        right_move_len: vec![],
                        prefix_val: vec![],
                        len: 0,
                        mark_all_flag: true,
                    }
                }
            } else {
                // 如果 目标网段 比 比较网段 更大
                let mut prefix_val_set:AHashSet<u32> = AHashSet::new();

                // 计算 比较网段 在 目标网段 中的前缀值
                for constraint_val in &self.prefix_val[index] {

                    let now_val = constraint_val >> ( tar_right_len - now_right_move_len );

                    // 如果 约束网段 是 目标网段 的 一部分, 那么前缀值应该相同
                    if now_val == common_prefix_val {
                        prefix_val_set.insert(*constraint_val);
                    }
                }

                if prefix_val_set.len() != 0 {
                    // 如果存在 有效约束网段
                    constraint_prefix_val.push(prefix_val_set);
                    constraint_right_move_len.push(now_right_move_len);
                }
            }
        }

        let new_len = constraint_right_move_len.len();

        Self {
            right_move_len: constraint_right_move_len,
            prefix_val:constraint_prefix_val,
            len: new_len,
            mark_all_flag: false,
        }
    }

    /// 判断指定 ip 是否被 标记, 黑名单被标记意味着被禁止, 白名单被标记意味着被放行
    pub fn ip_is_marked(&self, ip_val:u32) -> bool {

        // 如果 设置了 全域标记, 所有合法地址都直接返回 被标记
        if self.mark_all_flag {
            return true
        }

        for i in 0..self.len {

            let now_prefix_val = ip_val >> self.right_move_len[i];

            if self.prefix_val[i].contains(&now_prefix_val) {

                // 如果对应 set 类型已经包含 该ip 对应的前缀值
                // 说明 该ip 的对应网段 已被标记
                return true

            }

        }

        // 如果查询完所有封锁的 前缀类型 后，依然没有符合的
        // 说明 该ip 没有被标记
        false

    }

}

/// 根据输入范围, 计算 目标子网
/// 返回值: ( 目标子网前缀值, 目标子网右移距离(32 - 前缀长度) )
fn common_prefix(start:u32, end:u32) -> (u32, u32) {

    // 计算异或值, 相同位为 0, 不同位为 1
    let xor = start ^ end;

    // 获取 异或值 前导零 的个数
    // 前面相同的位数, 同时也是子网前缀的位数
    let common_len = xor.leading_zeros();

    if common_len != 0 {
        // 计算 目标子网 前缀值
        let right_move = 32 - common_len;
        let prefix_val = start >> right_move;

        (prefix_val, right_move)
    } else {
        // 如果 共同前缀 长度为 0
        (0, 32)
    }
}
