use crate::modes;
use crate::modes::Helper;
use crate::modules::{output_modules, probe_modules};

///  mode helper
pub fn mode_help(mode_name:&str) -> String {

    match mode_name {


        "cycle_v4" | "c4"  => modes::v4::CycleV4::print_help(),

        "cycle_v6" | "c6" => modes::v6::CycleV6::print_help(),

        "cycle_v6_pattern" | "c6p" => modes::v6::CycleV6Pattern::print_help(),

        "file_v4" | "f4" => modes::v4::V4FileReader::print_help(),

        "file_v6" | "f6" => modes::v6::V6FileReader::print_help(),

        "cycle_v4_v6" | "c46" => modes::mix::CycleV4V6::print_help(),

        "pmap_v4" | "p4" => modes::v4::PmapV4::print_help(),

        "pmap_v6" | "p6" => modes::v6::PmapV6::print_help(),

        "topo_v4" | "t4" => modes::v4::Topo4::print_help(),
        
        "topo_v6" | "t6" => modes::v6::Topo6::print_help(),

        "ipv6_addrs_gen" => modes::v6::SpaceTree6::print_help(),

        _ => {
            "no mode help".to_string()
        }
    }

}


/// probeV4 helper
pub fn probe_v4_help(name:&str) -> String {

    match name {


        "icmp_v4"  => probe_modules::probe_mod_v4::IcmpEchoV4::print_help(),

        "tcp_syn_scan_v4" => probe_modules::probe_mod_v4::TcpSynScanV4::print_help(),
        "tcp_syn_ack_scan_v4" => probe_modules::probe_mod_v4::TcpSynAckScanV4::print_help(),
        "tcp_syn_opt_v4" => probe_modules::probe_mod_v4::TcpSynOptV4::print_help(),

        "udp_scan_v4" => probe_modules::probe_mod_v4::UdpScanV4::print_help(),


        "topo_udp_v4" => probe_modules::topology_probe::topo_mod_v4::TopoUdpV4::print_help(),
        "topo_icmp_v4" => probe_modules::topology_probe::topo_mod_v4::TopoIcmpV4::print_help(),
        "topo_tcp_v4" => probe_modules::topology_probe::topo_mod_v4::TopoTcpV4::print_help(),

        _ => {
            "no help".to_string()
        }
    }

}

/// probeV6 helper
pub fn probe_v6_help(name:&str) -> String {

    match name {

        "icmp_v6"  => probe_modules::probe_mod_v6::IcmpEchoV6::print_help(),

        "tcp_syn_scan_v6" => probe_modules::probe_mod_v6::TcpSynScanV6::print_help(),
        "tcp_syn_ack_scan_v6" => probe_modules::probe_mod_v6::TcpSynAckScanV6::print_help(),
        "tcp_syn_opt_v6" => probe_modules::probe_mod_v6::TcpSynOptV6::print_help(),

        "udp_scan_v6" => probe_modules::probe_mod_v6::UdpScanV6::print_help(),

        "topo_udp_v6" => probe_modules::topology_probe::topo_mod_v6::TopoUdpV6::print_help(),
        "topo_icmp_v6" => probe_modules::topology_probe::topo_mod_v6::TopoIcmpV6::print_help(),
        "topo_tcp_v6" => probe_modules::topology_probe::topo_mod_v6::TopoTcpV6::print_help(),
        
        "code_icmp_v6" => probe_modules::active_probe_ipv6_code::CodeIcmpEchoV6::print_help(),

        _ => {
            "no help".to_string()
        }
    }

}


/// output helper
pub fn output_help(name:&str) -> String {

    match name {


        "csv"  => output_modules::Csv::print_help(),

        _ => {
            "no help".to_string()
        }
    }

}






