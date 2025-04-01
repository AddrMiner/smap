## 常见问题

### 无法打开黑名单或白名单文件

一般是初次安装时，在Do you need to keep the resource files (please confirm that all resource files are working properly) (y or ..):问题上输入了`y`。

可以重新安装，并注意在回答该问题时选择直接回车。也可以手动复制对应文件。

### 无法获取默认网络接口 

!> 或 **无法获取网络接口对应的网关信息** 

可能处于系统代理或其它一些特殊网络环境中，请关闭代理重试。

在有些情况下，可能是因为系统无法获取网关硬件地址导致的，此时需要使用 `-i 接口名称  -g 接口名称@该接口对应的网关硬件地址` 进行手动指定。在系统能够正常获取网关信息的情况下，用户指定的信息无效。 

### 输入smap提示不存在此命令

主要是因为安装时在`Whether to add the program path to the environment variable(y or ..):`问题上未回答`y`，或者未按提示（如`source ~/.bashrc`）刷新终端。

