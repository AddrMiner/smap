use std::process::exit;
use std::sync::Arc;
use log::error;
use crate::modules::target_iterators::pmap::graph::Graph;
use crate::modules::target_iterators::pmap::ip::IpStruct;
use crate::SYS;

impl IpStruct {

    #[inline]
    pub fn send_port(&mut self, graph:&Arc<Graph>) -> u16 {

        if let Some(s) = &self.state {
            // 如果 该地址 之前存在过状态

            // 绝对概率表索引是否可用的标志
            let mut ab_index_avail = true;
            // 绝对概率表索引是否可用的标志
            let mut relative_index_avail = true;

            // 将 绝对概率表索引 移动到 可用索引
            {
                loop {
                    // 绝对概率表索引 不能大于等于 绝对概率表 本身的长度
                    if self.ab_index >= graph.port_cnt { ab_index_avail = false;break }

                    if self.port_is_avail_in_ab( // 不在 更新概率表, 且不在 已探开放端口列表 和 已探未开放端口列表中
                                                 &graph.recommend_ports[self.ab_index], &s.port_to_ptr) { break }

                    self.ab_index += 1;
                }
            }

            // 将 相对概率表索引 移动到 可用索引
            {
                // 判断是否保持 当前状态
                // 如果为 true, 相对概率表索引将被顺延
                // 如果为 false, 相对概率表索引将被置为0
                if !self.remain_state { self.state_index = 0 }

                // 相对概率表长度
                let relative_table_len = s.ports.len();
                loop {
                    // 相对概率表索引 不能大于等于 相对概率表 本身的长度
                    if self.state_index >= relative_table_len { relative_index_avail = false;break }

                    // 判断 目标端口 是否在 开放端口列表 或 非开放端口列表 中存在, 不存在 返回 true
                    if self.port_is_avail(&s.ports[self.state_index].port) { break }

                    self.state_index += 1;
                }
            }

            // 获取推荐端口
            if ab_index_avail &&  relative_index_avail {
                // 如果 绝对概率表 和 相对概率表 同时可用

                let port_in_relative_table = &s.ports[self.state_index];
                if graph.recommend_ports_probability[self.ab_index] < port_in_relative_table.probability {
                    // 如果 绝对概率表中索引对应端口的概率 小于 相对概率表中索引对应端口的概率
                    // 应将 相对概率表中的对应端口 作为 待推荐端口

                    let next_port = port_in_relative_table.port;
                    self.state_index += 1;
                    self.cur_sent_port = next_port;
                    next_port
                } else {
                    // 如果 绝对概率表中索引对应端口的概率 大于等于 相对概率表中索引对应端口的概率
                    // 应将 绝对概率表中的对应端口 作为 待推荐端口

                    let next_port = graph.recommend_ports[self.ab_index];
                    self.ab_index += 1;
                    self.cur_sent_port = next_port;
                    next_port
                }
            } else if relative_index_avail {
                // 如果 相对概率表 可用

                // 将 相对概率表中的对应端口 作为 待推荐端口
                let next_port = s.ports[self.state_index].port;
                self.state_index += 1;
                self.cur_sent_port = next_port;
                next_port
            } else if ab_index_avail {
                // 如果 绝对概率表 可用

                // 将 绝对概率表中的对应端口 作为 待推荐端口
                let next_port = graph.recommend_ports[self.ab_index];
                self.ab_index += 1;
                self.cur_sent_port = next_port;
                next_port
            } else {
                // 如果 绝对概率表 和 相对概率表 均不可用

                let next_port = self.get_tar_port_out_of_graph(graph);
                self.cur_sent_port = next_port;
                next_port
            }
        } else {
            // 如果 该地址 没有状态

            if self.ab_index >= graph.port_cnt {
                // 如果 该地址的绝对概率表指针 已经超出范围

                let next_port = self.get_tar_port_out_of_graph(graph);
                self.cur_sent_port = next_port;
                return next_port
            }

            // 从 绝对概率表 中取得 下一个待推荐端口, 并直接返回
            let next_port = graph.recommend_ports[self.ab_index];
            self.ab_index += 1;
            self.cur_sent_port = next_port;
            next_port
        }
    }



    /// 当 概率相关图 不可用于 端口推荐 时, 使用 预设端口向量, 或逐个遍历所有端口号的方式得到 待推荐端口
    #[inline]
    fn get_tar_port_out_of_graph(&mut self, graph:&Arc<Graph>) -> u16 {

        while self.tar_ports_index < graph.tar_ports_len {
            // 如果 目标端口向量索引 在 目标端口向量 有效范围
            // 以 目标端口向量索引 为索引, 从目标端口向量中按顺序取出推荐端口

            let next_port = graph.tar_ports[self.tar_ports_index];
            if self.port_is_avail(&next_port) {
                // 如果 当前端口 可用
                self.tar_ports_index += 1;
                return next_port
            }

            // 如果 当前端口不可用, 目标端口向量索引加一, 查找下一个可用端口
            self.tar_ports_index += 1;
        }

        // 如果遍历过了所有端口, 仍需要推荐端口
        // 直接报错
        error!("{}", SYS.get_info("err", "tar_ports_index_err"));
        exit(1)
    }

}