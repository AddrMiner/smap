
# IPv6 别名前缀检测工具

## 基本用法

```shell
smap -m ac6 \
     -f <地址文件路径> \
     -a prefix_len=64 \
     -a rand_addr_len=16 \
     -a alia_ratio=0.8 \
     -a output_alia_addrs=true \
     -b 10m \
     -a prefixes_len_per_batch=1000000
```

## 参数说明

| 参数                     | 类型   | 默认值  | 说明                                                         |
| ------------------------ | ------ | ------- | ------------------------------------------------------------ |
| `-f`                     | string | 必填    | 待检测的IPv6地址文件路径                                     |
| `prefix_len`             | int    | 64      | 要检测的前缀长度                                             |
| `prefix_count`           | int    | 1000000 | 预估的前缀数量（用于内存优化）                               |
| `rand_addr_len`          | int    | 16      | 为每个前缀生成的随机地址数量                                 |
| `alia_ratio`             | float  | 0.8     | 别名判定阈值（0.0-1.0，必须包含小数点）<br>当响应地址数 ≥ 该值×随机地址数时判定为别名前缀 |
| `output_alia_addrs`      | bool   | false   | 是否输出被判定为别名前缀下的具体地址                         |
| `prefixes_len_per_batch` | int    | 1000000 | 每批次处理的前缀数量                                         |
| `-b`                     | string | 10m     | 探测速率（10Mb/秒），注意较大的探测速率可能会引发探测目标的ICMPv6速率限制 |

## 注意事项

!> 注意**冷却时间**和**batch_size**（发送函数发送多少个数据包后进行一次速率控制）等参数的影响

!> `alia_ratio`参数必须包含小数点（如`1.0`而非`1`）

!> 增大`prefixes_len_per_batch`可提升处理速度，但会占用更多内存