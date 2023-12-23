pub mod pcap;


pub struct ReceiverInfoV4{

    pub recv_validation_passed:u64,
    pub recv_validation_failed:u64,

    pub recv_success:u64,
    pub recv_failed:u64,
    pub recv_repeat:u64,
}

impl ReceiverInfoV4 {

    pub fn new() -> Self {
        Self {
            recv_validation_passed: 0,
            recv_validation_failed: 0,
            recv_success: 0,
            recv_failed: 0,
            recv_repeat: 0,
        }
    }

}



pub struct ReceiverInfoV6 {

    pub recv_validation_passed:u128,
    pub recv_validation_failed:u128,

    pub recv_success:u128,
    pub recv_failed:u64,
    pub recv_repeat:u128,
}

impl ReceiverInfoV6 {
    pub fn new() -> Self {
        Self {
            recv_validation_passed: 0,
            recv_validation_failed: 0,
            recv_success: 0,
            recv_failed: 0,
            recv_repeat: 0,
        }
    }

}

