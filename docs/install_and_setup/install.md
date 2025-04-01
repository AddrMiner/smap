## 安装流程

**SMap** 的安装流程一般如下流程图所示：

```mermaid
flowchart LR
    A[安装Rust环境] --> B[编译准备]
    B --> C[在安装目录下使用安装脚本]
    C --> D[配置源地址白名单]
```

## 安装RUST语言环境

!> 在安装时需要自定义默认编译目标（也可在安装后手动切换）。   
**Linux** 下需调整为 **x86_64-unknown-linux-gnu**    
**Windows** 下需调整为 **stable-x86_64-pc-windows-gnu**

请参照 [官方安装文档](https://www.rust-lang.org/tools/install) 进行安装

## 编译准备

> 打开 **SMap代码根目录** 下的 **sys_conf.ini** ，修改**默认配置**和**提示语句**。

**编译时**将读取该文件并写入程序。**除非重新编译，该文件中的配置将永远保持不变**。

**SMap**的**所有提示语句均由本文件写入**，可通过修改该文件中的提示信息来将本程序翻译成另一种语言。

## 安装

在 **SMap根目录** 下根据系统平台选择对应的安装指令，并按提示输入安装路径或选择默认安装路径。

!>  1.  确认**当前设备RUST配置**的**默认编译目标**正确          
2.  安装时应**保持联网状态**   
3.  注意**不要将安装路径设置在源代码路径**    
4.  Windows环境中应使用**终端**应用运行该Powershell脚本   
5.  **如果自定义安装路径**，则路径的最下级必须为本程序的名称，如 D:\smap      
6.  需要在**管理员**（Windows）或**ROOT**（Linux、Unix）权限下安装
7.  请注意脚本的问题

### Windows

```powershell
.\install_windows.ps1
```

### Linux

```shell
./install_linux.sh
```

### Mac

```shell
./install_macos.sh
```

### 安装脚本询问

`Enter install path or press Enter for default` 输入安装路径

一般情况下直接`Enter`使用默认路径进行安装

`Do you need to keep the resource files (please confirm that all resource files are working properly) (y or ..): ` 是否保存资源文件？

如果需要保存原来的配置（如黑白名单等），回答`y`；如果**首次安装**或不需要保留原来配置则直接`Enter`。

#### Windows特有询问

`Have Npcap been installed and SDK configured(y or ..)`: 是否已经安装过**npcap**并且其SDK可用？

如果确定安装过npcap及其SDK，请回答`y`；如果是**首次安装**或不清楚是否安装过，请直接`Enter`。

#### Linux特有询问

` Whether to add the program path to the environment variable(y or ..): ` 是否加入环境变量？

   如果**首次安装**需要回答`y`或`yes`；如果已经安装过SMap并添加过环境变量则直接`Enter`。


## 使用前配置

!> **源地址检查器会自动过滤私有地址和标记网段**，无论是**自动从系统中获取**的还是**手动输入**的**均会受到审查**。如果需要使用**私有地址**作为**源地址**，如**校园网**，**企业及家庭内部网络**，**手机热点**等需要将本地网络加入源地址白名单。

!> 某些特殊情况下，系统**无法获取网关硬件信息**，此时需要使用 `-i 接口名称  -g 接口名称@该接口对应的网关硬件地址` 进行手动指定。在系统能够正常获取网关信息的情况下，用户指定的信息无效。 

检查目的地址和源地址黑白名单配置（路径：**安装路径**下的**block_list**文件夹，可输入**不加任何参数**的命令**smap**获取当前安装路径），黑白名单支持 **域名（该域名对应的多个地址同时加入），单个地址，网段**。