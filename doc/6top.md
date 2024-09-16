# 6Top参数

- budget: 扫描预算，即发送数据包的数量
- divide_dim: 划分维度， 一般默认为4
- learning_rate: 学习率
- max_prefix_len: 最大前缀长度， 一般默认为64
- min_prefix_len: 最小前缀长度，一般为48
- seeds_path: 种子地址路径
- prefix_path: 前缀列表文件路径(pyasn离线数据库)
- min_target_num: 最小目标数量，当某一拓扑探测轮次生成的<ip,ttl>组合数量小于该值时，将结束对当前所有目标前缀的探测
- rand_ord: 是否随机选择分裂节点
- allow_supplement_scan: 是否允许辅助扫描(在探测结束后使用yarrp6目标前缀生成方案)
- threshold: 节点优势水平下限，当某个节点的优势水平低于该值时，该节点将被立即丢弃
- extra_node_num: 节点抽取数量，默认为1万
- initial_ttl: 每个目标地址的初始ttl值， 一般默认为16
- gap_limit: 允许的最大连续沉默数量
- prefix_tree_max_ttl: 前缀树算法所允许的最大ttl值
- allow_leaf_expand: 是否允许叶子节点扩展
- child_max_size: 一个节点一次性最多能分裂出多少子节点