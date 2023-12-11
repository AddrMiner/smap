pub mod pcap;


pub struct ReceiverInfoV4{

    pub validation_passed:u64,
    pub validation_failed:u64,

    pub success_total:u64,
    pub failed_total:u64,
    pub repeat_total:u64,
}

impl ReceiverInfoV4 {

    pub fn new() -> Self {
        Self {
            validation_passed: 0,
            validation_failed: 0,

            success_total: 0,
            failed_total: 0,
            repeat_total: 0,
        }
    }

}



pub struct ReceiverInfoV6 {

    pub validation_passed:u128,
    pub validation_failed:u128,

    pub success_total:u128,
    pub failed_total:u64,
    pub repeat_total:u128,
}

impl ReceiverInfoV6 {
    pub fn new() -> Self {
        Self {
            validation_passed: 0,
            validation_failed: 0,

            success_total: 0,
            failed_total: 0,
            repeat_total: 0,
        }
    }

}

