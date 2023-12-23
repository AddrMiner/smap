use std::sync::Arc;
use ahash::AHashMap;
use crate::modules::target_iterators::pmap::graph::Graph;
use crate::modules::target_iterators::pmap::ip::IpStruct;
use crate::modules::target_iterators::pmap::state::State;
use crate::tools::others::insert::insert_to_sorted_array;

impl IpStruct {

    pub fn receive(&mut self, is_not_opened:bool, graph:&Graph, states_map:&mut AHashMap<String, Arc<State>>) {

        if is_not_opened {
            // 如果 当前端口 为关闭状态

            // 如果没有新的活跃端口, 该地址的对应状态将保持不变
            self.remain_state = true;

            // 使用插入排序, 将新的 未开放端口 插入 未开放端口列表(注意: 从小到大排序)
            insert_to_sorted_array(&mut self.not_open_ports, self.cur_sent_port);

        } else {
            // 如果 当前端口 为开放状态

            if let Some(p) = &self.state {
                // 如果 该地址 之前存在状态

                if Arc::strong_count(p) < 3 {
                    // 强引用计数 小于3
                    // 若 强引用计数 等于 1, 说明仅有该地址引用该状态, 这种情况一般只有在异常情况下出现
                    // 若 强引用计数 等于 2, 说明仅有 该地址 和 状态库 引用该状态

                    // 从 状态库 中尝试 删除该地址对应的原状态
                    let pre_state_label = self.get_label();
                    states_map.remove(&pre_state_label);
                }

                // 使用插入排序, 将新的 开放端口 插入 开放端口列表(注意: 从小到大排序)
                insert_to_sorted_array(&mut self.open_ports, self.cur_sent_port);

                // 更新后的 状态标签
                let new_state_label = self.get_label();
                if let Some(s) = states_map.get(&new_state_label) {
                    // 如果 更新后的状态标签 在 状态库 中存在

                    // 更新 当前地址 状态指针
                    self.state = Some(s.clone());
                } else {
                    // 如果 更新后的状态标签 在 状态库 中不存在, 需要新建状态

                    // 从 现有状态 生成 新状态
                    let new_state = State::new_state_from_exist(self.cur_sent_port, p, graph);
                    if new_state.ports.len() != 0 {

                        // 改变状态
                        self.remain_state = false;

                        let new_sate = Arc::new(new_state);

                        // 将 新状态 插入 状态库, 键为 新状态对应的标签
                        states_map.insert(new_state_label, new_sate.clone());

                        // 将 新状态指针 链接到 该地址
                        self.state = Some(new_sate);
                    } else {
                        // 如果没有有效的新状态, 该地址的对应状态将保持不变
                        self.remain_state = true;
                    }
                }
            } else {
                // 如果 该地址 之前没有状态

                // 使用插入排序, 将新的 开放端口 插入 开放端口列表(注意: 从小到大排序)
                insert_to_sorted_array(&mut self.open_ports, self.cur_sent_port);

                // 更新后的 状态标签
                let new_state_label = self.get_label();
                if let Some(s) = states_map.get(&new_state_label) {
                    // 如果 更新后的状态标签 在 状态库 中存在

                    // 更新 当前地址 状态指针
                    self.state = Some(s.clone());
                } else {
                    // 如果 更新后的状态标签 在 状态库 中不存在, 需要新建状态

                    // 生成 新状态
                    let new_state = State::new_state_from_none(self.cur_sent_port, graph);
                    if new_state.ports.len() != 0 {

                        // 改变状态
                        self.remain_state = false;

                        let new_sate = Arc::new(new_state);

                        // 将 新状态 插入 状态库, 键为 新状态对应的标签
                        states_map.insert(new_state_label, new_sate.clone());

                        // 将 新状态指针 链接到 该地址
                        self.state = Some(new_sate);
                    } else {
                        // 如果没有有效的新状态, 该地址的对应状态将保持不变
                        self.remain_state = true;
                    }
                }
            }
        }
    }
}