## 概述

**SMap**中内置了四种类型的探测模块，分别用于**活跃探测**，**拓扑与路由接口探测**，以及前两者的**自定义编码**探测模块。自定义编码模块用于**区域编码**等特定扫描技术，提高探测性能。

探测模块在`src/modules/probe_modules`的对应目录下编写，一般需要实现两个源文件：

- `mod.rs` 包括探测模块**定义**，用于构造的`new()`函数，以及用于线程初始化的`init()`函数，还有帮助接口。
- `method.rs` 为探测模块实现对应探测模块方法的特质。

!> 每个探测模块都需要在对应的地方进行声明。  
如IPv6活跃探测模块需要在`src/modules/probe_modules/active_probe/probe_mod_v6.rs`中的`PROBE_MODS_V6`数组进行声明，并在`new()`和`init()`中进行对接。

## 探测模块示例
!> 下文中验证为对探测的真实响应但并非正常响应的**不能**作为**判断地址是否存活**或**判断端口是否开放**的依据。  
比如，**ICMP差错报文不能作为地址存活的依据**，**TCP RST响应报文不能作为端口开放的依据**。  
SMap的活跃探测模块默认只输出**正常响应**，非正常响应（如RST响应）请使用参数`--allow_no_succ`。

### ICMPv6活跃地址探测模块

> ICMPv6活跃地址探测模块构造和发送ICMPv6请求数据包，并通过解析响应数据包来判断目标地址是否存活。模块路径：`src/modules/probe_modules/active_probe/v6/icmp/icmp_echo`
#### 时序图

```mermaid
sequenceDiagram
    participant 探测端
    participant 目标主机

    Note over 探测端: 构造ICMPv6请求数据包</br>使用<源地址，目的地址>生成AES验证数据</br>密文用于填充ICMP ID和ICMP data部分
    
    探测端->>目标主机: 发送ICMPv6请求包

    Note right of 目标主机: alt表示分支情况
    alt 收到Echo Reply
        目标主机-->>探测端: ICMP Type=129
        探测端->>探测端: 使用响应数据包的<目的地址，源地址>进行AES加密</br>还原出验证数据</br>验证ID+Data是否与构造的数据包一致
    Note over 探测端: 验证通过即为正常回声响应
    else 收到ICMP差错报文
        目标主机-->>探测端: ICMP Type=1-4
        探测端->>探测端: 解析嵌套的内层ICMP原始报文(原始探测数据包)</br>使用内层数据包的<源地址，目的地址>进行AES加密</br>还原出验证数据</br>验证内层原始数据包的ID+Data
    Note over 探测端: 验证通过说明是对探测的真实响应</br>但并非正常响应
    end
    Note left of 探测端: 验证失败则说明</br>响应数据包不是对探测的正确响应</br>或者关键信息被中途篡改</br>验证失败的响应数据包将被立即丢弃
```

### TCP SYN开放端口探测模块

> TCP SYN开放端口探测模块构造和发送TCP SYN请求数据包，并通过解析响应数据包来判断目标地址上的目标端口是否开放。模块路径：`src/modules/probe_modules/active_probe/v4/tcp/tcp_syn_scan`

#### 时序图

```mermaid
sequenceDiagram
    participant 探测端
    participant 目标主机

    Note over 探测端: 构造TCP SYN请求数据包</br>使用❗<源IP，目标IP，目标端口>❗生成AES验证数据</br>将验证数据用于序列号和源端口选择

    探测端->>目标主机: SYN包(Flags=SYN)

    alt 收到SYN-ACK响应
        目标主机-->>探测端: SYN-ACK包
        探测端->>探测端: 使用❗响应数据包的<目的IP，源IP，源端口>❗生成AES验证数据</br>验证目的端口是否与构造的源端口一致</br>根据验证数据还原出构造的序列号</br>验证响应数据包中的确认号是否为构造的序列号加一
        Note over 探测端: 验证成功即标记为开放端口
    else 收到RST响应
        目标主机-->>探测端: RST包
        探测端->>探测端: 与SYN-ACK响应数据包处理一致
        Note over 探测端: 验证通过说明是对探测的真实响应</br>但不能说明端口开放
    else 收到ICMP差错报文
    	目标主机-->>探测端: ICMP差错报文
    	探测端->>探测端: 与ICMPv6探测模块的处理类似</br>区别是使用嵌套数据包的<源IP,目的IP，目的端口>生成验证数据</br>并使用验证数据检查源端口等信息是否正确
        Note over 探测端: 验证通过说明是对探测的真实响应</br>但不能说明端口开放
    end
    Note left of 探测端: 验证失败则说明</br>响应数据包不是对探测的正确响应</br>或者关键信息被中途篡改</br>验证失败的响应数据包将被立即丢弃
```
