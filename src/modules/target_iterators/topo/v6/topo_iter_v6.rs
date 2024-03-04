use rand::rngs::StdRng;
use crate::modules::target_iterators::cycle_group::Cyclic;

pub struct  TopoIterV6 {

    // 索引迭代器
    pub p:u128,
    pub prim_root:u128,
    pub p_sub_one:u128,

    // 经过乘法群计算, 应用于探测的 当前目标 和 最后一个目标值
    pub current:u128,
    pub last:u128,

    // 根据 ip 占的比特位数计算得到的 目标值有效范围
    pub valid_range:u128,



    // 基础ip值
    pub base_ip_val:u128,

    // ip 片段的位移量
    // (0: 第一次左移位数, 1: 右移位数, 2: 第二次左移位数)
    pub ip_move_len:Vec<(u32,u32,u32)>,

    //     [ 地址1                              , 地址2, ...  ]
    //     [ u8(  下一个ttl | 是否接收到响应(1比特)), u8, ....   ]
    // 注意: 已接收响应为1, 未接收响应为0
    pub state_chain:Vec<u8>,

    // 相对于 总状态链 的起始索引
    pub start_index:usize,
}


impl TopoIterV6 {
    pub fn new(start_index:usize, state_chain:Vec<u8>, base_ip_val:u128, ip_move_len:Vec<(u32, u32, u32)>, rng: &mut StdRng) -> Self {

        let tar_ip_num = state_chain.len() as u64;

        // 获得 乘法循环群
        let cycle = Cyclic::new(tar_ip_num, rng, u128::MAX);

        let mut ori_iter = Self {
            p: cycle.p,
            prim_root: cycle.prim_root,
            p_sub_one: cycle.p_sub_one,

            // 这里只做初始化, 没有实际意义
            current: 0,
            last: 0,

            valid_range: (tar_ip_num as u128) + 1,
            base_ip_val,
            ip_move_len,
            state_chain,
            start_index,
        };

        ori_iter.init();
        ori_iter
    }

    pub fn init(&mut self){

        // 转换成对应大数
        let big_p = Cyclic::parse_u128_to_big_num(self.p);
        let big_prim_root = Cyclic::parse_u128_to_big_num(self.prim_root);
        let big_start = Cyclic::parse_u128_to_big_num(1);
        let big_end  = Cyclic::parse_u128_to_big_num(self.p_sub_one);

        // 计算 根据当前乘法群遍历到的 第一个目标(索引) 和 最后一个目标  prim_root^(start) % p
        let big_first = big_prim_root.modpow(&big_start, &big_p);
        let big_last  = big_prim_root.modpow(&big_end, &big_p);

        self.current = Cyclic::parse_big_num_to_u128(big_first);
        self.last =  Cyclic::parse_big_num_to_u128(big_last);
    }
}
