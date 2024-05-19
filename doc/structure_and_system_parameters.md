## 结构概览

<img src="https://cdn.sa.net/2023/12/30/F6K4qU5C8BpNlM1.png" alt="smap.png" style="zoom: 50%;" />

## core

### 概述

该部分为本程序的核心部分, 主要包括 配置解析, 接收函数, 发送函数, 系统调用.

### conf

**set_conf**: 基础配置, 接收配置, 发送配置 的配置模块

**args**: 命令行参数设置

**sys_config**: sys_conf.ini的解析模块

**modules_config**: 自定义参数的解析模块

**tools**: 参数解析, 网络接口硬件解析等

### receiver

各种接收函数及其对应的包处理函数

注意: 自定义的接收函数应当与base同级, 参照pmap实现

### sender

**v4**: ipv4发送函数

**v6**: ipv6发送函数

**tools**: 发送函数的辅助类, 如PID速率控制器, 源地址迭代器等.

注意: 自定义的发送函数应当与base同级, 参照pmap实现

### sys

**packet_sender**: 各操作系统平台的发包函数

**logger**: 系统日志配置

## modes

### 概述

模式是本程序的核心, 一般由 定义结构体(包括帮助信息接口), 构造函数, 执行函数三个部分构成. 

定义结构体中定义需要使用的全局参数, 如基础配置, 发送配置, 探测模块, 拦截器等. 

构造函数以命令行参数为输入, 由开发者决定构造目标和构造逻辑.

执行函数以构造函数构造好的结构体为基础, 执行由用户定义的探测逻辑, 并由用户决定是否进行记录和输出, 以及记录和输出哪些内容.

### 注意事项

- 模式的创建应该符合规范, 在对应mod下以独立文件夹形式创建独立的mod. 
- mod内的rs文件一般命名为mod, new, execute, 分别对应定义函数, 构造函数, 执行函数. 注意execute函数和帮助函数必须调用对应接口, 构造函数需要符合规范. 如需创建更多rs源文件, 请使用tools.rs或tools文件夹.
- 所有可用模式必须在modes文件夹下的mod.rs中进行挂载, 且在MODES数组中进行声明.
- **模式, ipv4探测模块,  ipv6探测模块, 输出模块** 的帮助函数需要在helper_mode下的modules_helper中挂载, 否则无效

### 子模块

**helper_mode** : 打印帮助信息的模块. 

**mix** : ipv4和ipv6混合模式

**v4** : ipv4模式

**v6** : ipv6模式

**macros** : 模式中的宏定义

## modules

### 概述

当前包括 输出模块, 探测模块, 目标迭代器模块 , 后续可能按需添加新的模块类别.

### output_modules

除记录文件(输入参数, 探测结果摘要)外, 所有输出均使用用户或模式选择的输出模块进行输出.

注意: 

- 输出模块原则上使用单个rs源文件.
- 输出模块需要实现 全局构造方法(new) 和 线程初始化函数(init) 并在output_modules的mod.rs下进行挂载.
- 输出模块需要在 OUTPUT_MODS 中进行声明.
- 输出模块需要实现 OutputMethod接口 和 帮助信息 接口.

### probe_modules

每个探测模块通常由 mod.rs 和 method.rs 构成.

mod.rs包括探测模块的定义, 全局构造方法, 线程初始化函数, 帮助信息函数. 每个探测模块均可以按照自身需要完全自定义所需的字段, 并进行完全自定义的构造过程和线程初始化. 

method.rs为探测模块实现探测方法接口. 在这一部分, 我们提供了一些基础探测模块的实现方法并力求为探测模块的编写设计一种简单, 直观, 高性能的代码规范. 建议参照我们预设的探测模块进行模块开发.

我们的探测模块与zmap的探测模块非常类似又稍有不同.  我们在编写探测模块时几乎照搬了zmap的核心逻辑, 但又对很多部分进行了性能上, 功能上, 简单直观上的改进, 并对可能导致问题的部分进行革除或修正.

注意:

- 探测模块的创建应该符合规范, 在对应mod下以独立文件夹形式创建独立的mod. 

- 探测模块应由 mod.rs 和 method.rs 两个源文件构成, 数据包的处理等应放置在 tools/net_handle/packet下.

- 探测模块需要实现 全局构造方法(new) 和 线程初始化函数(init)

- ipv4探测模块需要实现 ProbeMethodV4 接口, ipv6探测模块需要实现 ProbeMethodV6 接口, 所有探测模块需要实现 帮助信息 接口

- 所有可用 ipv4 探测模块应在 probe_mod_v4.rs 中进行挂载并在 PROBE_MODS_V4 中进行声明.

- 所有可用 ipv6 探测模块应在 probe_mod_v6.rs 中进行挂载并在 PROBE_MODS_V6 中进行声明.

### target_iterators

目标迭代器是各类探测算法的核心. 比如, 1.活跃地址生成推荐算法本质上解决的是接下来需要探测哪些目标的问题, 2.活跃端口推荐算法本质上解决的是接下来需要探测哪些目标的哪些端口的问题, 3.其它算法,比如拓扑探测中的目标,生存时间组合以及在一定网段进行随机地址生成以诱发icmp错误来发现一些有价值目标等, 本质上都是某种类型的目标迭代算法. 

迭代对象一般包括并不限于, 地址, 地址端口对, 地址ttl(或hop_limit)组合, 地址特定载荷组合等. 我们将常见的类别抽象为特质, 迭代器需要实现其中的某种, 或自定义新的特质来使之适用于特定类型的发送接收函数, 或将之作为更高级的迭代器中的一部分.

基础迭代器现在包括乘法循环群迭代器(包括ipv4, ipv6, ipv6模式字符串, 以及它们的带端口版本), 文件迭代器(按照是否已知目标数量分为 按字节数量分割的文件迭代器 和 按目标数量分割的文件迭代器), 活跃端口推荐迭代器(pmap_v4, pmap_v6), 后续我们将陆续加入活跃地址推荐算法迭代器, 拓扑探测迭代器, 以及别的一些重要的迭代算法.

## tools

### blocker

黑白名单拦截器, 主要用来筛选有效源地址和避免向一些网段发送探测数据包. 

我们设计的拦截器算法能有效应对超大规模的黑白名单列表, 在内存中存储的有效信息(数组)一定小于黑白名单本身的大小. 单次匹配的最大计算次数仅为有效局部约束的网段种类数量(有效局部约束网段种类 <= 前缀聚合后的网段种类 <= 网段种类 <= 地址二进制位长度 ). 有效局部约束为正在探测的目标网段中包含的标记网段(标记网段在当前的目标网段之中), 且支持跟随目标范围变化快速动态调整.

我们设计的拦截器与其它部分完全独立, 这意味着您可以在任何场景中不受限制地使用它.

### check_duplicates

目标查重器, 主要用在接收线程中对重复目标进行检查, 或在一些避免即时输出的场景(以pmap为例)中用作探测结果的记录器.

目标查重器一般使用位图, 哈希表, 布隆过滤器(Bloom Filter)等实现. 为准确性考虑, 当前只默认提供基于位图和哈希表的查重器, 如需要进行超大规模测量且可以接受一定的误识别率(如果 `contains` 返回 `true` , 则可能在过滤器中. 如果 `contains` 返回 false，则绝对不在布隆过滤器中)时, 建议调用[growable-bloom-filter](https://crates.io/crates/growable-bloom-filter).

此模块下的mod.rs文件定义了各种常用接口, 查重器算法需要实现其中的某些接口或自定义新的接口以应用于特定类型的接收函数.

### encryption_algorithm

执行密钥生成, 随机数生成, 加密载荷, 数据包校验等功能的模块.

### file

文件操作模块.主要用于获取路径, 解析文本, 写入文件等.

### net_handle

用于处理网络数据的工具库

- **dns** : 用于dns解析的各种函数
- **net_interface** : 处理网络硬件接口, 硬件地址定义及其工具函数等.
- **net_type** : 网段定义, 网络类型定义, 及其相关工具函数.
- **packet** : 数据包定义, 数据包生成, 数据包解析函数, 字段定义及其解析函数, 其它各种与数据包处理相关的工具函数.

### others

其他各类工具函数和底层算法, 如 排序算法, 查找算法, 字符串解析函数, 时间处理等.

## 系统参数(sys_conf.ini)

以下所有设置中涉及到的路径, 如果为绝对路径则完全为用户指定路径, 如果为相对路径则以安装路径为起始位置.可输入不带参数的smap指令获取当前安装路径.

- summary_file: 记录文件路径. 注意不要以 .扩展名 的形式结尾, 系统会根据使用的模式, 目标将该路径填充为

  ```shell
  设置的路径_模式名称_目标名称.csv
  ```

- default_output_mod: 默认输出模块名称

- default_send_attempt_num: 发送失败后进行重试的默认次数

- default_source_ports: 默认源端口范围. **注意: 由于一部分探测模块将源端口作为验证条件, 原则上该范围必须足够大,推荐万级以上.**

- default_probe_mod_v4: 默认ipv4探测模块. 除非有绝对必要, 一般不要修改此选项, 建议保持默认探测模块为icmp探活模块.

- default_probe_mod_v6: 默认ipv6探测模块. 除非有绝对必要, 一般不要修改此选项, 建议保持默认探测模块为icmp探活模块.

- default_batch_size: 发送线程连续发送数据包的最小单位. 速率控制器在每个最小发送单位中至少执行一次速率控制函数.

- default_must_sleep: 发送线程发送一个最小单位后至少等待的时间, 以 **微秒** 为单位.

- default_cool_time: 发送线程结束到关闭接收线程之间的默认等待时间.

- default_ports: 默认目标端口. 除非有绝对必要, 一般不要修改此选项. 注意: **网络层协议探测模块会对目标端口是否为0进行检查.**

- output_file_pattern_v4: ipv4结果输出文件路径, 可使用%d %m %Y %H %M等模式字段, 这些模式字段将自动置换为当前时间, 请参照[DateTime in chrono](https://docs.rs/chrono/0.4.31/chrono/struct.DateTime.html#method.format)

- output_file_pattern_v6: ipv6结果输出文件路径, 可使用%d %m %Y %H %M等模式字段, 这些模式字段将自动置换为当前时间, 请参照[DateTime in chrono](https://docs.rs/chrono/0.4.31/chrono/struct.DateTime.html#method.format)

- default_output_buffer_capacity: 输出缓冲区默认大小, 以字节为单位

- active_check_count: 接收线程每隔多少个活跃数据包检查一次管道消息

- capture_timeout: 捕获器的读取超时. 设为0时将无限期阻塞.

- pcap_recv_buffer_size: pcap接收缓冲区大小

- get_socket_attempts: 获取系统socket失败后的重试次数

- attempt_sleep_millis: 发送失败后睡眠的毫秒数, 只有在设置发送失败后进行睡眠的发送函数中才有效.

- kp: pid算法的p参数. 只有您确认自己的修改目的并预期到合理结果时才能修改此配置.

- ki: pid算法的i参数. 只有您确认自己的修改目的并预期到合理结果时才能修改此配置.

- ki_limit: pid算法的稳态误差限制参数.  当 稳态误差 大于 $  abs(ki\_limit * tar\_rate) $ 时, 稳态误差将被置0. 只有您确认自己的修改目的并预期到合理结果时才能修改此配置.

- kd: pid算法的d参数. 只有您确认自己的修改目的并预期到合理结果时才能修改此配置.

- destination_black_list_v4: ipv4目的地址黑名单默认路径.

- destination_white_list_v4: ipv4目的地址白名单默认路径.

- source_black_list_v4: ipv4源地址黑名单默认路径.

- source_white_list_v4: ipv4源地址白名单默认路径.

- destination_black_list_v6: ipv6目的地址黑名单默认路径.

- destination_white_list_v6: ipv6目的地址白名单默认路径.

- source_black_list_v6: ipv6源地址黑名单默认路径.

- source_white_list_v6: ipv6源地址白名单默认路径.

- fallback_bytes: 文件迭代器目标范围回退字节数

- max_read_buf_bytes: 文件迭代器最大读取缓冲区大小

- default_payload_file: 探测模块载荷文件路径

- log_pattern: 日志格式, 参见 [log_pattern](https://docs.rs/log4rs/*/log4rs/encode/pattern/index.html)

- log_name_pattern: 日志文件名称格式, 在手动指定日志目录时有效. 可使用%d %m %Y %H %M等模式字段, 这些模式字段将自动置换为当前时间, 请参照[DateTime in chrono](https://docs.rs/chrono/0.4.31/chrono/struct.DateTime.html#method.format)

- running_time_pattern: 运行时间显示格式, 可使用 {d} {h} {m} {s}等标识字段, 系统将按照实际运行时间进行替换.

- forecast_completion_time_pattern: 预期完成时间显示格式, 参照 [DateTime in chrono](https://docs.rs/chrono/0.4.31/chrono/struct.DateTime.html#method.format)

### AddrMiner-S 系统参数

- default_code_probe_mod_v6: 默认编码探测模块
- space_tree_type: 空间树类型
- budget: 默认预算
- batch_size: 每轮次的预算(每轮次最大生成数量)
- divide_dim: 划分维度, 如4代表半字节划分
- divide_range: 划分范围, 指的是按照地址结构哪部分进行分裂, 其它部分将在输入时置换为0. 如设为1-64, 所有地址的后64位将被置换为0, 且不作为分裂和生成的部分
- max_leaf_size: 聚类区域种子地址数量上限(小于等于该数量的节点不再继续分裂)
- no_allow_gen_seeds: 不允许生成种子地址(但是可以生成输入文件中不用作种子地址的其它地址)
- no_allow_gen_seeds_from_file: 不允许生成输入文件中的任何地址, 如果此项为真, no_allow_gen_seeds将强制为真
- learning_rate: 学习率
- region_extraction_num: 区域抽取数量, 每次地址生成时将选择前n个区域(奖励最大排名), n是区域抽取数量和队列长度中的最小值
- seeds_num: 种子地址数量, 从输入文件中随机选取指定数量个地址作为种子地址


### Pmap系统参数

- pmap_default_ports: pmap默认目标端口范围
- pmap_default_probe_mod_v4: pmap_v4默认探测模块名称
- pmap_default_probe_mod_v6: pmap_v6默认探测模块名称
- pmap_sampling_pro: pmap默认采样比例(预扫描比例)
- pmap_min_sample_num: pmap最小采样数量(预扫描目标地址数量)
- pmap_budget: pmap端口推荐默认预算
- pmap_batch_num: pmap推荐扫描默认轮次(如: 如果其值设为10, 就将推荐扫描阶段的所有目标地址分为10份, 对其中的一份全部扫描(所有推荐端口)完毕后进行对下一份的扫描, 其间根据用户的设定选择是否对概率相关图进行更新)
- pmap_allow_graph_iter: 是否允许概率相关图更新的默认值
- pmap_use_hash_recorder: 是否默认使用哈希表作为记录器. 如果设为真, 默认以哈希表(适用总范围较大且推荐轮次较多的情形)作为记录器, 如果设为假, 默认以位图(适用总范围较小且活跃比例较高的情形)作为记录器.

### topo系统参数

- topo_max_ttl: 默认最大ttl, 最大值不超过64
- topo_udp_dest_port: 拓扑探测模块默认udp端口
- topo_payload: 拓扑探测模块默认负载
- topo4_rand_bits: ipv4模式字符串随机比特位(于固定比特位有效)
- topo4_default_probe_mod: topo4默认拓扑探测模块
- topo6_rand_bits: ipv6模式字符串随机比特位(于固定比特位有效)
- topo6_default_probe_mod: topo6默认拓扑探测模块
