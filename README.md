# SMap: 为科研和专职工作者开发的网络探测器

smap是专为科研和专业从事人员设计的高性能网络探测器.  

smap的突出特征: 简洁, 全面可扩展, 完全的可定制性, rust语言程序特有的高性能和高稳定性. 在保证极致性能的同时, 让任何人都能以数百行甚至更低的成本实现绝大多数现有网络探测器的功能, 或者以相同的成本完全从零开始实现一种全新的网络探测工具.

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

对模式的构造函数和执行函数进行编写非常简单. 我们在构造函数中将通常一起出现的配置封装, 用户只需要按需调用对应函数并接收配置结构体, 比如基本配置, 发送配置, 接收配置等. 这些配置之间又是相互独立的, 比如:如果您不需要进行数据包发送, 就可以不构造发送配置.  执行函数中则设置了大量的宏, 它封装了一些常见的代码范式, 并可调用内置的各种发送接收函数. 这些发送接收函数同样可以深度定制, 通常只需要复制粘贴后调整少量代码.

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

##### Windows(管理员权限)

   ```powershell
   .\install_windows.ps1
   ```

##### Linux(root)

```shell
./install_linux.sh
```

##### Mac os(root)

```shell
./install_macos.sh
```



