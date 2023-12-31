# SMap: 为科研和专职工作者设计的网络探测器

smap是专为科研和专业从事人员设计的高性能网络探测器.  

smap的突出特征: 简洁, 全面可扩展, 完全的可定制性, rust语言程序特有的高性能和高稳定性. 在保证极致性能的同时, 让任何人都能以数百行甚至更低的成本实现绝大多数现有网络探测器的功能, 或者以相同的成本从零开始实现一种全新的网络探测工具.

我们简洁的主函数由接收参数, 配置日志, 创建模式, 执行模式四个简单部分组成, 除了参数接收和日志配置以外的所有部分由用户决定. 一般来说, 用户只需要简单地调用框架提供的底层模块, 并按照自己的逻辑进行组合, 就可以快速实现一个完全自定义的网络探测器.

```rust
fn main() {
    let mode;
    {
        let args = Args::get_args();	// 获取命令行参数
        set_logger(&args);		// 配置 系统日志
        mode = Mode::new(&args);	// 选择并创建模式
    }
    mode.execute();	// 执行模式
}
```

smap的核心是模式(mode), 通常由定义结构体, 构造函数, 执行函数三部分组成. 我们提供了一些基础模式, 比如与zmap相同功能的cycle_v4模式以及它的ipv6和ipv6字符串版本, 通过文件读取地址或地址端口对的file_reader模式, 以及与masscan类似功能的cycle_v4_v6模式. 请注意, 尽管用户可以使用这些模式进行基础的网络测量任务, 但它们的主要作用是为用户自定义的模式提供模板, 用户可以按照自己的实际需求参照对应的基础模式进行开发, 或者以基本模式为模板简单地进行局部修改. 

编写模式的构造函数和执行函数非常简单. 我们在构造函数中将通常一起出现的配置封装, 用户只需要按需调用对应函数并接收配置结构体, 比如基本配置, 发送配置, 接收配置等. 这些配置之间又是相互独立的, 比如:如果您不需要进行数据包发送, 就可以不构造发送配置.  执行函数中则设置了大量的宏, 它封装了一些常见的代码范式, 并可调用内置的各种发送接收函数. 这些发送接收函数同样可以深度定制, 通常只需要复制粘贴后调整少量代码.

与zmap相同, 我们的探测模块, 输出模块完全独立, 此外还有模块化的迭代器部分. 我们为探测模块的开发提供接口, 代码格式样例, 常用的宏定义和工具函数, 帮助您快速开发或从其他语言转译.

## 安装

smap支持 Windows, Linux, Macos, Bsd等主流平台.

### rust环境

参照官方文档进行安装

[Other Installation Methods - Rust Forge (rust-lang.org)](https://forge.rust-lang.org/infra/other-installation-methods.html)

### 构建和安装

#### 编译准备

1. 打开 **smap根目录** 下的 **sys_conf.ini** , 修改默认配置和提示语句. 

   编译时将读取该文件并写入程序. 除非重新编译, 该文件中的配置将永远保持不变. 

   smap的所有提示语句均由本文件写入, 可通过修改该文件中的提示信息来将本程序翻译成另一种语言

2. 打开 **smap根目录** 下的 **Cargo.toml** , 根据系统平台和实际需要调整必要设置. 

   *警告*: Linux环境下需要将 [profile.release] 下的 opt-level 设置为 0, 否则无法发送数据包. 其它平台建议设为3. 目前并不清楚编译优化等级为什么会导致无法发送数据包, 推测可能是指针定位问题, 相关路径为src\core\sys\packet_sender\linux\packet_sender.rs

#### 安装

在 **smap根目录** 下根据系统平台选择对应的安装指令, 并按提示输入安装路径或选择默认安装路径.

注意:

- 安装时应保持联网状态
- 自定义的安装路径必须包含本程序的名称, 如 D:\Smap

##### Windows (管理员权限)

   ```powershell
   .\install_windows.ps1
   ```

##### Linux (root)

```shell
./install_linux.sh
```

##### Macos (root)

```shell
./install_macos.sh
```

## 用法

### 前置配置

检查目的地址和源地址黑白名单配置(路径: 安装路径下的block_list文件夹, 可输入命令smap获取当前安装路径), 黑白名单支持 **域名(该域名对应的多个地址同时加入), 单个地址, 网段**.

**注意: 源地址检查器会自动过滤私有地址和标记网段, 无论是自动从系统中获取的还是手动输入的均会受到审查. 如果需要使用私有地址作为源地址, 如校园网, 企业及家庭内部网络, 需要将本地网络加入源地址白名单.**

### 快速开始

#### Ipv4示例

以10m速率对 **单个**ipv4[**地址, 范围, 网段**] 进行 **icmp存活** 扫描

注: 如需同时对**多个不连续的ip[地址, 范围, 网段]**进行探测, 请参考下面的**混合示例**或实现自定义模式,下同

```shell
smap -m c4 -b 10m -t 171.67.70.0/23
```

以10m速率对 单个ipv4[**地址, 范围, 网段**] 进行 **tcp_syn端口** 扫描

```shell
smap -m c4 -b 10m --probe_v4 tcp_syn_scan_v4 -t 110.242.68.5 -p 80,442-443
```

以10m速率对 ipv4[**地址文件,  地址端口对文件**] 进行 **icmp存活** 扫描

```shell
# 注意: 文件名中可以使用 _num目标数量_  _min最小ip值_  _max最大ip值_ 等标记优化扫描
# ip值类型: u32(ipv4) 或 u128(ipv6), 如: test_num10_min0_max10_.txt
smap -m f4 -b 10m -f your_path
```

以10m速率对 ipv4[**地址文件,  地址端口对文件**] 进行 **tcp_syn端口** 扫描

```shell
# 未指定端口, 将从文件中读取
# 格式:  地址|端口 , 注意每行是一个端口对, 如果 某行 为地址, 其端口将被置为0 
# 如需对同一目标进行多端口探测, 请设置为多行, 如:
# 地址1|端口1
# 地址1|端口2
smap -m f4 -b 10m --probe_v4 tcp_syn_scan_v4 -f your_path

# 指定端口, 忽略文件中的端口, 按指定端口进行探测
# 如果指定为0, 将从文件文件读取
# 如指定端口为 0,80,443 , smap将对所有端口对进行 文件指定端口,80,443端口 共计三种端口的探测
# 注意地址不要重复
smap -m f4 -b 10m --probe_v4 tcp_syn_scan_v4 -f your_path -p 0,22,443
```

#### Ipv6示例

以10m速率对 单个ipv6[**地址, 范围, 网段**] 进行 **icmp存活** 扫描

```shell
smap -m c6 -b 10m -t 2001:1208:ffff:ffff:ffff:ffff:ffff:e/126
```

以10m速率对 单个ipv6[**地址, 范围, 网段**] 进行 **tcp_syn端口** 扫描

```shell
smap -m c6 -b 10m --probe_v6 tcp_syn_scan_v6 -t 240e:83:205:58:0:ff:b09f:36bf -p 80,442-443
```

以10m速率对 ipv6[**地址文件,  地址端口对文件**] 进行 **icmp存活** 扫描

```shell
smap -m f6 -b 10m -f your_path
```

以10m速率对 ipv4[**地址文件,  地址端口对文件**] 进行 **tcp_syn端口** 扫描

```shell
# 未指定端口, 将从文件中读取  格式同ipv4
smap -m f6 -b 10m --probe_v6 tcp_syn_scan_v6 -f your_path

# 指定端口, 忽略文件中的端口, 按指定端口进行探测  格式同ipv4
smap -m f6 -b 10m --probe_v6 tcp_syn_scan_v6 -f your_path -p 0,22,443
```

#### Ipv6模式字符串示例

以10m速率对 单个ipv6[**模式字符串**] 进行 **icmp存活** 扫描

```shell
# 使用@字符标志模式位, 模式位将被置为01全排列
# 如模式位为 61-64,128 则将该ipv6的 相应位 置为01全排列, 共计32个目标ip
smap -m c6p -b 10m -t 2001:1218:101:11d::1@61-64,128

# 如果不使用@标志, 将默认为二进制模式字符串, *字符标记的模式位将被置为01全排列
# 除 0, 1, * 以外的其它字符将被忽略, 可用_符号等做长度标记
smap -m c6p -b 10m -t 001000000000000100010010000110000000000100000001000000010001****_000000000000000000000000000000000000000000000000000000000000000*
```

以10m速率对 单个ipv6[**模式字符串**] 进行 **tcp_syn端口** 扫描

```shell
smap -m c6p -b 10m --probe_v6 tcp_syn_scan_v6 -t 2001:1218:101:11d::1@61-64,128 -p 80,442-443
# 或
smap -m c6p -b 10m --probe_v6 tcp_syn_scan_v6 -t 001000000000000100010010000110000000000100000001000000010001****_000000000000000000000000000000000000000000000000000000000000000* -p 80,442-443
```

#### 混合示例

以10m速率对 **多个**ipv4, ipv6[**地址, 范围, 网段**] 进行 **icmp存活** 扫描

**注: 该模式下ipv4和ipv6可同时出现, 也可以只有ipv4或只有ipv6**

**警告: 同时进行ipv4和ipv6探测可能会导致更大的性能消耗和时间消耗. 如非必要请不要使用, 尤其是在一些对性能和探测时间要求严格的任务中.**

```shell
smap -m c46 -b 10m -t 220.181.38.149-220.181.38.150,42.81.179.153,20.76.201.171,240e:c2:1800:166:3::3d7-240e:c2:1800:166:3::3d8,240e:928:1400:1000::25,2603:1020:201:10::10f
```

以10m速率对 **多个**ipv4, ipv6[**地址, 范围, 网段**] 进行 **tcp_syn端口** 扫描

```shell
smap -m c46 -b 10m --probe_v4 tcp_syn_scan_v4 --probe_v6 tcp_syn_scan_v6 -t 220.181.38.149-220.181.38.150,42.81.179.153,20.76.201.171,240e:c2:1800:166:3::3d7-240e:c2:1800:166:3::3d8,240e:928:1400:1000::25,2603:1020:201:10::10f -p 80,442-443
```

#### 结果保存

smap的所有扫描记录(扫描时间, 参数, 探测结果摘要), 探测结果(存活的地址列表, 地址端口对列表等)等文件默认存放在安装目录. 记录文件的文件夹名为records,  探测结果的文件夹名为result. 您可以通过修改sys_conf.ini或传入对应参数的方式修改这些设置. 相对路径以安装路径为起始路径, 绝对路径由用户指定, 传入参数优先级大于sys_conf.ini配置的优先级.

#### pmap

pmap专为同一网络内的全端口范围活跃端口扫描任务进行设计

以10m速率对 单个ipv4[**地址, 范围, 网段**] 进行 **tcp_syn端口**  活跃推荐扫描

```shell
smap -m p4 -b 10m -t 42.81.179.50-42.81.179.180 -p 80,443,22,21,53 -a pmap_sampling_pro=0.1 -a pmap_budget=2 -a pmap_batch_num=2
```
以10m速率对 单个ipv6[**模式字符串**] 进行 **tcp_syn端口**  活跃推荐扫描

```shell
smap -m p6 -b 10m -t 240e:928:1400:105::b@125-128 -p 80,443,22,21,53 -a pmap_sampling_pro=0.1 -a pmap_budget=2 -a pmap_batch_num=2
```

### 选项字段及开发者文档

- 详细的命令行参数信息请参照 [选项文档](./doc/options.md)

- 项目结构及系统参数信息请参照 [结构与系统参数文档](./doc/structure_and_system_parameters.md)

##  License and Copyright

SMap Copyright 2023 

Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See LICENSE for the specific language governing permissions and limitations under the License.
