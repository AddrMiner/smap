### IPv4

#### IPv4 乘法循环群命令解析与迭代器构造

```rust
let (start_ip, end_ip, tar_ip_num) = parse_ipv4_cycle_group(addrs_str:&str);
```

参数：IPv4地址范围，如 `10.10.0.0/16` 或 `10.10.0.1-10.10.0.220`

输出：（起始IP地址，最终IP地址，该范围内IP地址总数） 

```rust
let c4 = CycleIpv4::new(start_ip:u32, tar_ip_num:u64, rng:&mut StdRng)
```

参数：起始地址，目标IP地址总数，随机数发生器

输出：IPv4（不包含端口）循环群迭代器

#### IPv4 文件迭代器构造

```rust
let mut targets = TargetFileReader::new(path:&String);
```

参数：目标文件路径

```rust
let (tar_ip_num, range_is_valid, first_tar, end_tar) = targets.parse_file_info_v4();
```

输出：目标地址数量（可能为空），目标地址范围是否可知，首个地址（如果能得到目标范围），最后一个地址（如果能得到目标范围）