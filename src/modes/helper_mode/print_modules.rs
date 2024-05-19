use crate::modes::MODES;
use crate::modules::output_modules::OUTPUT_MODS;
use crate::modules::probe_modules::active_probe_ipv6_code::CODE_PROBE_MODS_V6;
use crate::modules::probe_modules::probe_mod_v4::PROBE_MODS_V4;
use crate::modules::probe_modules::probe_mod_v6::PROBE_MODS_V6;
use crate::modules::probe_modules::topology_probe::topo_mod_v4::TOPO_MODS_V4;
use crate::modules::probe_modules::topology_probe::topo_mod_v6::TOPO_MODS_V6;
use crate::SYS;

/// 打印所有模式
pub fn print_modes(){

    println!("{}", SYS.get_info("print","print_modes"));

    for mode in MODES {
        print!("{}  ",mode);
    }

    print!("\n");
}

/// 打印所有ipv4探测模块
pub fn print_probe_v4_modules(){

    println!("{}", SYS.get_info("print","print_probe_v4_modules"));

    for probe in PROBE_MODS_V4 {
        print!("{}  ", probe);
    }

    for probe in TOPO_MODS_V4 {
        print!("{}  ", probe);
    }

    print!("\n");
}


/// 打印所有ipv6探测模块
pub fn print_probe_v6_modules(){

    println!("{}", SYS.get_info("print","print_probe_v6_modules"));

    for probe in PROBE_MODS_V6 {
        print!("{}  ", probe);
    }

    for probe in TOPO_MODS_V6 {
        print!("{}  ", probe);
    }

    for probe in CODE_PROBE_MODS_V6 {
        print!("{}  ", probe);
    }

    print!("\n");
}


/// 打印所有输出模块
pub fn print_output_modules(){

    println!("{}", SYS.get_info("print","print_output_modules"));

    for output in OUTPUT_MODS {
        print!("{}  ", output);

    }

    print!("\n");
}


