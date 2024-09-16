# IPv6 Aliased Prefixes Checker参数

- f: 待检测的地址文件路径
- prefix_len: 前缀长度, 默认为64
- prefix_count: 已知或预测的前缀数量, 仅用于优化内存占用，默认为100万
- rand_addr_len: 每个前缀生成的随机地址数量
- alia_ratio: 别名阈限， 当一个前缀响应地址数量达到   别名阈限*每前缀随机地址数量 时，该前缀被计为别名前缀, 取值范围(0.0,1.0], 注意必须带小数点
- output_alia_addrs: 是否统计并输出别名前缀下的别名地址
- prefixes_len_per_batch: 每轮次对多少前缀进行探测, 默认为100万