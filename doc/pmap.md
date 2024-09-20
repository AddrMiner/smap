# Pmap
- pmap_sampling_pro: pmap采样比例(预扫描比例)
- pmap_min_sample_num: pmap最小采样数量(预扫描目标地址数量)
- pmap_budget: pmap端口推荐预算
- pmap_batch_num: pmap推荐扫描轮次(如: 如果其值设为10, 就将推荐扫描阶段的所有目标地址分为10份, 对其中的一份全部扫描(所有推荐端口)完毕后进行对下一份的扫描, 其间根据用户的设定选择是否对概率相关图进行更新)
- pmap_allow_graph_iter: 是否允许概率相关图更新
- pmap_use_hash_recorder: 是否使用哈希表作为记录器. 如果设为真, 默认以哈希表(适用总范围较大且推荐轮次较多的情形)作为记录器, 如果设为假, 默认以位图(适用总范围较小且活跃比例较高的情形)作为记录器.
- pmap_port_num_limit: 开放端口超过该限制的地址将被视为异常地址, 不参与概率相关图训练