# Pmap 智能端口扫描工具

## 概述
Pmap专为同一网络内的全端口范围活跃端口扫描优化设计。通过先对部分目标进行全端口扫描，分析端口开放概率关系，智能推荐剩余目标的扫描端口。

## 扫描模式

### IPv4网络扫描
```shell
smap -m p4 \
     -b 10m \
     -t 42.81.179.50-180 \
     -p 80,443,22,21,53 \
     -a pmap_sampling_pro=0.1 \
     -a pmap_budget=2 \
     -a pmap_batch_num=2
```

### IPv6模式字符串扫描
```shell
smap -m p6 \
     -b 10m \
     -t 240e:928:1400:105::b@125-128 \
     -p 80,443,22,21,53 \
     -a pmap_sampling_pro=0.1 \
     -a pmap_budget=2 \
     -a pmap_batch_num=2
```

### IPv6文件输入模式
```shell
smap -m pf6 \
     -b 10m \
     --batch_size 1 \
     -f your_path \
     -p 80,443,22,21,53 \
     -a pmap_sampling_pro=0.1 \
     -a pmap_budget=2 \
     -a pmap_batch_num=2
```

> **注意事项**：
> - 该模式无法使用位图记录器
> - 黑名单拦截机制无效
> - 建议设置较小的batch_size值

## 核心参数说明

| 参数                     | 类型  | 默认值 | 说明                             |
| ------------------------ | ----- | ------ | -------------------------------- |
| `pmap_sampling_pro`      | float | 无     | 预扫描采样比例 (0.0-1.0)         |
| `pmap_min_sample_num`    | int   | 无     | 最小预扫描目标数量               |
| `pmap_budget`            | int   | 无     | 端口推荐预算值                   |
| `pmap_batch_num`         | int   | 无     | 推荐扫描轮次数                   |
| `pmap_allow_graph_iter`  | bool  | true   | 是否允许概率图更新               |
| `pmap_use_hash_recorder` | bool  | true   | 使用哈希表(而非位图)作为记录器   |
| `pmap_port_num_limit`    | int   | 无     | 开放端口数超过此值的地址视为异常 |

## 参数选择建议
1. **采样比例**：通常设为0.1-0.3，网络规模越大取值可越小
2. **记录器选择**：  
   • 哈希表：适合大规模网络/多轮次扫描  
   • 位图：适合小规模网络/高活跃度场景