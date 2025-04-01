## 乘法循环群迭代器

乘法循环群迭代器是一种用于**连续目标范围**的目标迭代器，广泛用于**IP网段、连续的IP范围、IPv6模式字符串、连续范围的IP和端口组合、连续范围的IP和跳数限制组合**等。

乘法循环群目标迭代器基于**ℤₚ\*的循环群特性**，利用原根的乘法生成性质构造目标地址序列，每次迭代通过**xₙ₊₁ = g·xₙ mod p**计算下一个地址。

### IPv4 目标迭代器

!> 注意**地址**，**地址端口对**，**地址模式字符串**，**地址模式字符串端口对**等不同目标迭代任务需要调用不同的迭代器类型。

!> 由于调用方法命名一致，此章节仅陈述**命令解析**和**迭代器构造**方法。

#### 命令解析

**地址范围**解析

```rust
let (start_ip, end_ip, tar_ip_num) = parse_ipv4_cycle_group(addrs_str:&str);
```

参数：IPv4地址范围，如 `10.10.0.0/16` 或 `10.10.0.1-10.10.0.220`

输出：（起始IP地址，最终IP地址，该范围内IP地址总数） 

#### IPv4 地址迭代器

```rust
let c4 = CycleIpv4::new(start_ip:u32, tar_ip_num:u64, rng:&mut StdRng)
```

参数：起始地址，目标IP地址总数，随机数发生器

输出：IPv4（不包含端口）循环群迭代器

#### IPv4 地址端口对迭代器

```rust
let c4p = CycleIpv4Port::new(start_ip:u32,tar_ip_num:u64,tar_ports:Vec<u16>, rng:&mut StdRng);
```

参数：起始地址，目标IP地址总数，目标端口列表，随机数发生器

输出：IPv4地址端口对循环群迭代器

### IPv6 地址迭代器

#### 命令解析

**地址范围**解析

```rust
let (start_ip, end_ip, tar_ip_num) = parse_ipv6_cycle_group(addrs_str:&str);
```

参数：IPv6地址范围

输出：（起始IP地址，最终IP地址，该范围内IP地址总数）

#### IPv6 地址迭代器

```rust
let c6 = CycleIpv6::new(start_ip:u128, tar_ip_num:u64, rng:&mut StdRng)
```

参数：起始地址，目标IP地址总数，随机数发生器

输出：IPv6（不包含端口）循环群迭代器

#### IPv6 地址端口对迭代器

```rust
let c6 = CycleIpv6Port::new(start_ip:u128,tar_ip_num:u64, tar_ports:Vec<u16>, rng:&mut StdRng)
```

参数：起始地址，目标IP地址总数，目标端口列表，随机数发生器

输出：IPv6地址端口对循环群迭代器

### IPv6 模式字符串迭代器

#### 命令解析

**模式字符串**解析

```rust
let (ip_bits_num, base_ip_val, mask, parts, max_ip) = if tar_ips_str.contains('@'){
    // 如果字符串中包含 @ 字符, 当作 一般模式字符串 处理
    parse_ipv6_pattern(tar_ips_str)
} else {
    // 如果不包含 @ 字符, 当作二进制字符串处理
    parse_ipv6_binary_pattern(tar_ips_str)
};
```

参数：IPv6模式字符串

输出：（地址所占的比特位总数，最小IP，掩码，片段信息，最大IP）  

地址所占的比特位总数与模式二进制位相等。

片段信息是一个可变连续片段组成的列表，每个片段包括以下信息：（片段长度，片段相对最低位的偏移量）。

最小IP是指将模式字符位置换成0后的值，最大IP是指将模式字符位置换成1后的值。

#### IPv6 地址模式串迭代器

```rust
let c6p = CycleIpv6Pattern::new(bits_for_ip:u32, base_ip_val:u128, parts:Vec<(u32, u32)>, rng:&mut StdRng)
```

参数：地址所占的比特位总数，最小IP，片段信息，随机数发生器

输出：IPv6模式字符串地址（不包含端口）循环群迭代器

#### IPv6 地址端口对迭代器

```rust
let c6p = CycleIpv6PatternPort::new(bits_for_ip:u32, base_ip_val:u128, parts:Vec<(u32, u32)>, tar_ports:Vec<u16>, rng:&mut StdRng)
```

参数：地址所占的比特位总数，最小IP，片段信息，目的端口列表，随机数发生器

输出：IPv6模式字符串地址端口对循环群迭代器

### 循环群线程初始化

```rust
let mut local_target_iter = cycle_iter.init(start_index:u64, end_index:u64);
```

从整体循环群为每个发送线程创建局部目标迭代器。各线程起止索引由`src/core/conf/tools/args_parse/target_iterator.rs`下以`cycle_group_assign`开头的工具函数进行计算。

### 循环群目标迭代

#### IP地址迭代

```rust
let first_ip = target_iter.get_first_ip();
let next_ip = target_iter.get_next_ip();
```

!> 由于乘法循环群特性，每个线程在获取第一个目标时必须使用`get_first_ip()`

获取后续目标使用`get_next_ip()`

返回值： （0:是否为非最终值, 1:最终值是否有效, 2:IP地址）

#### IP地址端口对迭代

```rust
let first_ip_port = target_iter.get_first_ip_port();
let next_ip_port  = target_iter.get_next_ip_port();
```

每个发送线程获取首个目标时需要使用`get_first_ip_port`，获取后续目标使用`get_next_ip_port`。

返回值： （0:是否为非最终值，1:最终值是否有效，2:IP地址，3:端口号）

## 文件迭代器

文件迭代器是从文本文件中读取探测目标并用于探测的迭代器算法。

### 构造函数

```rust
let mut file_reader = TargetFileReader::new(path:&String);
```

### 解析文件基本信息

> 此处得到的信息，如**目标数量**、**最小目标地址**、**最大目标地址**等可用于优化**扫描控制**，**目标拦截器**等底层算法的效率。

#### IPv4文件信息解析

```rust
let (tar_num, range_is_valid, first_tar, end_tar) = targets.parse_file_info_v4();
```

#### IPv6文件信息解析

```rust
let (tar_num, range_is_valid, first_tar, end_tar) = targets.parse_file_info_v6();
```

返回值：（目标数量，目标范围是否有效，最小目标，最大目标）

### 线程局部迭代器

#### 多线程目标分配

```rust
let assigned_target_range = targets.assign(thread_num:u64)
```

#### IPv4局部迭代器

```rust
let local_target_iter = target_iter.get_ipv4_file_reader(assigned_targets:&(u64,u64,u64), cur_tar_port:u16);
```

#### IPv6局部迭代器

```rust
let local_target_iter = target_iter.get_ipv6_file_reader(assigned_targets:&(u64,u64,u64), cur_tar_port:u16);
```

参数：由`assign`得到的目标分配区间，当前需要探测的端口（0为无效端口，设置0将按照文件中地址附带的端口进行探测）

输出：局部迭代器

### 文件迭代器目标迭代

```rust
let mut next_target = target_iter.get_next_ip_port();
```

返回值：（0:是否为非最终值，1:当前值是否有效，2:ip地址，3:端口号）























