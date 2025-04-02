## 概述
AddrMiner-S 是基于 **IPv6密度空间树** 的地址生成算法，此版本结合区域编码技术（6Scan）。  

!>  输入文件中的地址需保持有序（密度空间树本身无需排序，排序仅用于地址分割时的去重）。

**示例命令**  

```shell
smap -m ipv6_addrs_gen \  
     -b 10m \  
     -f 输入文件路径 \  
     -a budget=500000 \  
     -a no_allow_gen_seeds=true \  
     -a region_extraction_num=1000 \  
     --cool_seconds 1
```

**示例参数说明**：  
• `-b 10m`：以每秒1000万地址的速率探测  
• `-f 输入文件路径`：种子地址文件路径  
• `--cool_seconds 1`：发送冷却时间1秒  
• `budget=500000`：生成50万个地址  
• `no_allow_gen_seeds=true`：禁止复用种子地址  
• `region_extraction_num=1000`：每次最多抽取1000个聚类区域  

## 参数列表

| 参数                           | 说明                                                         |
| ------------------------------ | ------------------------------------------------------------ |
| `space_tree_type`              | 空间树类型（如密度空间树）                             |
| `budget`                       | 生成地址的总数量                                  |
| `batch_size`                   | 每轮生成的地址数量上限                                       |
| `divide_dim`                   | 划分维度（例如 `4` 表示按半字节划分）                        |
| `divide_range`                 | 划分范围（如 `1-64` 表示仅对地址前64位分裂，其余置零）       |
| `max_leaf_size`                | 聚类区域种子数上限（≤此值的节点不再分裂）                    |
| `no_allow_gen_seeds`           | 禁止生成种子地址（但仍可生成输入文件中的其他地址）                     |
| `no_allow_gen_seeds_from_file` | 禁止生成输入文件中的任何地址（启用时会强制 `no_allow_gen_seeds=true`） |
| `learning_rate`                | 学习率                             |
| `region_extraction_num`        | 每次生成时提取的聚类区域数量（按奖励排名前N个）              |
| `seeds_num`                    | 从输入文件中随机选取的种子地址数量                           |

