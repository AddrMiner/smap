use std::time::Duration;
use chrono::Utc;
use std::thread::sleep;
use crate::core::conf::set_conf::sender_conf::RateGlobalConf;
use crate::SYS;

pub struct RateController{

    tar_rate:f64,

    // pid 算法
    kp:f64,
    ki:f64,
    ki_limit:f64,
    kd:f64,

    integral_term:f64,
    prev_m:Option<f64>,


    start_time:i64,
    batch:f64,

    // 这里使用f64纯粹性能考虑, 注意f64的整数位精度只有2^(53),
    // 再往上加会导致精度出现误差, 每进一位会 *2, 最多为 2^(11)误差
    // 根据误差大小, 这里并不限制到 64 位的转换, 因为影响微乎其微
    total_count:f64,

    // 以 微妙 计的 每轮次必须睡眠时间
    must_sleep:u64,

    total_delay:u64,
    batch_count:u64,
}


impl RateController {


    pub fn new(tar_rate: f64, batch:f64, must_sleep:u64) -> Self{

        // 注意 f64 精度
        let tar_rate = tar_rate / 1_000_000.0;   //   每秒多少目标 转换为 每微秒多少


        RateController {
            tar_rate,

            // kp:0.8, ki:0.02, ki_limit:0.05, kd:0.1

            // kp:0.8,
            // ki:0.02,
            // ki_limit:0.05,
            // kd:0.1,

            kp: SYS.get_conf("conf","kp"),
            ki: SYS.get_conf("conf","ki"),
            ki_limit: SYS.get_conf("conf","ki_limit"),
            kd: SYS.get_conf("conf","kd"),


            integral_term:0.0,
            prev_m:None,

            must_sleep,                 // 必须休眠的时间

            start_time: Utc::now().timestamp_micros(),
            batch,

            total_count:0.0,
            total_delay:0,
            batch_count:0,

        }
    }


    pub fn from_conf(conf:&RateGlobalConf, tar_num:u64, batch_size:f64) -> Self {

        if conf.running_time < 0.0 {
            // 如果 running_time 参数无效
            // 直接按照全局速率进行发送
            Self::new(conf.tar_rate, batch_size, conf.must_sleep)
        } else {
            if tar_num == 0 {
                // 注意: 在给各个线程分配任务时不可为0目标
                // 如果该值为0, 表明该值无效

                // 如果目标数量无效, 按照全局指导速率进行发送
                Self::new(conf.tar_rate, batch_size, conf.must_sleep)
            } else {
                // 使用当前 探测目标数量 与 预期运行时间 计算当前线程的发送速率
                // 发送速率 = 目标数量 / 预期运行时间(以秒为单位)
                let thread_send_rate = (tar_num as f64) / conf.running_time;

                Self::new(thread_send_rate, batch_size, conf.must_sleep)
            }
        }
    }


    #[inline]
    pub fn sleep(&mut self){       // 在每个轮次结束后执行，用来获得下一轮次每个数据包之间的发送间隔

        self.batch_count += 1;
        self.total_count += self.batch;

        let now_time = Utc::now().timestamp_micros();
        let used_time_micros = now_time - self.start_time;       // 总时间
        let now_total_rate = self.total_count  / (used_time_micros as f64);     // 总速率

        let aver_delay_time =  self.total_delay / self.batch_count;  // 计算过去的平均延迟，并将此作为基准

        // pid 控制
        let pid_out = self.next_control_output(now_total_rate);
        // ( pid_out + now_total_rate )  *  ( used_time_micros  +  ?  ) = self.total_count

        let pid_rate = pid_out + now_total_rate;        // 计算指导速率
        let pid_time = self.total_count / pid_rate;     // 使用指导速率反推指导时间

        let pid_delay_time = (pid_time as i64) - used_time_micros;        // 计算指导时间 与 实际时间的差值
        // 修正 总延迟

        let now_delay_time;
        if pid_delay_time < 0 {
            let pid_sub = (-pid_delay_time) as u64;

            if pid_sub < aver_delay_time {
                now_delay_time = aver_delay_time - pid_sub;
            } else {
                now_delay_time = 0;
            }

        } else {
            now_delay_time = aver_delay_time + (pid_delay_time as u64);
        }




        if now_delay_time > self.must_sleep {
            self.total_delay  +=  now_delay_time;
            sleep(Duration::from_micros(now_delay_time));
        } else {
            self.total_delay  +=  self.must_sleep;
            sleep(Duration::from_micros(self.must_sleep));
        }


    }

    #[inline]
    fn next_control_output(&mut self, measurement:f64) -> f64{


        let error = self.tar_rate - measurement;

        let p = error * self.kp;
        self.integral_term = self.integral_term + error * self.ki;

        if (self.integral_term > (self.ki_limit * self.tar_rate)) || (self.integral_term < (-self.ki_limit * self.tar_rate)) {
            self.integral_term = 0.0;
        }

        let d = -match self.prev_m.as_ref() {
            Some(pre_ref) => measurement - *pre_ref,
            None => 0.0,
        } * self.kd;
        self.prev_m = Some(measurement);


        p + self.integral_term + d
    }


}

