## 概要

smap [ -m  <模式名> ]   [ 选项.. ]   [ -a  <自定义参数名称=自定义参数值> ]

## 描述

smap是一个面向科研人员和专职工作者的高性能网络探测器. 支持快速地全面深度定制, 灵活适应各种可能的需求. 

### 基本选项

- **-m**  |  **--mode**  : 基础模式或用户定义模式的名称. 各个模式之间从参数解析, 配置设置, 执行过程到结果输出的所有过程完全独立. **注意: 如果不使用该选项, 将进入帮助模式.**

- **-i** |  **--interface** :  指定的本机网络接口名称. smap支持同时调用多个网络接口, 示例如:

  ```shell
  smap -m mode_name  -i interface_name_1  -i interface_name_2 -i interface_name_3  ...
  ```

  注意:  发送和接收函数的第一个参数为网络接口索引(从0开始), 基础模式通常默认只调用第一个网络接口

- **-a** : 用户, 模式, 探测模块等 指定的**自定义参数**,  注意对同一变量名重复赋值会导致覆盖, 示例如:

  ```shell
  smap -m mode_name -a name_1=val_1 -a name_2=val_2 -a name_3=val_3  ...
  ```

- **--probe_v4** : Ipv4探测模块名称, 用以指定对ipv4地址进行探测时使用的探测模块, 与ipv6探测模块相互独立互不影响

- **--probe_v6** : Ipv6探测模块名称, 用以指定对ipv6地址进行探测时使用的探测模块, 与ipv4探测模块相互独立互不影响

### 发送选项

- **-t** | **--tar_ips** : 设置目标ip地址范围, 注意目标地址范围的格式因模式不同而异

- **-f** | **--target_file** : 设置主目标路径, 适用于单目标文件传入的模式, 或多目标文件模式中的主目标文件夹路径

- **-p** | **--tar_ports** : 目标端口范围. 如:  **\*** 或 **a-b,c-d,e**  ,**\*** 在这里表示全部端口

- **-b** | **--band_width** : 发送带宽设置(K, M, G), 注意带宽和发送速率不能同时设置

- **--send_rate** : 一秒发送数据包的数量, 注意带宽和发送速率不能同时设置

- **--saddr** : 用以发送数据包的源地址范围, 如:a-b(ipv4),c-d(ipv6),e,f/10(ipv4). 支持用,分割开的不同范围, 支持同时输入ipv4和ipv6地址, 支持单个地址, 网段, 范围.  注:(ipv4) 和 (ipv6)表示前面的地址为ipv4或ipv6, 请不要输入 (ipv4) 或 (ipv6)

- **--sport** : 用以发送数据包的源端口范围. 如:  **\*** 或 **a-b,c-d,e**  , **\*** 在这里表示全部端口

- **--send_thread_num** : 发送线程数量

- **--send_attempt_num** : 发送数据包时的重试次数(如果发送失败, 最多会尝试多少次)

- **--batch_size** : 每个发送轮次的大小

- **--must_sleep** : 每个发送轮次执行完毕后必须等待的时间

- **--cool_seconds** : 所有发送线程结束后到接收线程结束前的冷却时间

### 接收选项

- **-o** | **--output** : 输出模块名称
- **--allow_no_succ** :  允许探测失败但验证成功的输出, 如Icmp包裹原始数据包, Rst标志数据包等
- **--output_file_v4** :  ipv4探测模块输出文件路径
- **--output_file_v6** :  ipv6探测模块输出文件路径
- **--filter** : 接收线程数据包过滤方法
- **--fields** : 输出字段. (如果不设置该选项, 一般情况下将输出全部字段)

### 黑白名单选项

- **--black_list_v4** : Ipv4黑名单路径

- **--black_list_v6** : Ipv6黑名单路径

- **--white_list_v4** : Ipv4白名单路径

- **--white_list_v6** : Ipv6白名单路径

- **--source_black_list_v4** : Ipv4源地址黑名单路径

- **--source_black_list_v6** : Ipv6源地址黑名单路径

- **--source_white_list_v4** : Ipv4源地址白名单路径

- **--source_white_list_v6** : Ipv6源地址白名单路径

### 帮助选项

- 无选项(输出命令为 smap ): 打印帮助提示信息, 所有 模式, 探测模块, 输出模块  的名称 以及 当前安装路径 

- **--mode_help** : 模式名称.  打印对应模式的帮助信息, 如:

  ```shell
  smap --mode_help  mode_name_1
  ```

- **--probe_v4_help** : ipv4探测模块名称.  打印对应ipv4探测模块的帮助信息

- **--probe_v6_help** : ipv6探测模块名称.  打印对应ipv6探测模块的帮助信息

- **--output_help** : 输出模块名称.  打印对应输出模块的帮助信息

### 日志选项

- **-q** | **--disable_sys_log** : 是否关闭日志终端输出

- **--log_level** : 日志等级 示例: 0 1 2 3 4 5 从0到5依次升高, 小写形式的 trace debug info warn error. 默认值为trace

- **--log_file** : 日志输出文件路径.  **注意: 未设置日志输出文件或日志输出目录的情况下, 将默认不将日志存储到文件.**

- **--log_directory** : 日志输出目录(在目录下创建规定格式的日志文件). **注意: 未设置日志输出文件或日志输出目录的情况下, 将默认不将日志存储到文件.**

### 其它选项

- **--seed** : 随机数种子, 用来 设置加密密钥 和 生成随机数

- **--summary_file** : 记录文件路径. 保存一次扫描的配置信息, 扫描结果等. 

  注意不要以 .扩展名 的形式结尾, 系统会根据使用的模式, 目标将该路径填充为

  ```shell
  设置的路径_模式名称_目标名称.csv
  ```