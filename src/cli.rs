use std::env;
use std::net::Ipv4Addr;
use std::collections::HashMap;

pub fn print_usage() {
    println!("Usage: route_tester <short_edge> [OPTIONS]");
    println!("Options:");
    println!("  -v, --verbose    Display detailed DNS response flags");
    println!("  -h, --help       Display this help message");
    println!("\nVerbose mode flags (True if displayed):");
    println!("  RESP          - This is a response");
    println!("  SQ            - Standard query");
    println!("  AA            - Authoritative Answer");
    println!("  TC            - Truncated response");
    println!("  REC           - Recursion provided");
    println!("  MATCH         - ID matched the request");
    println!("  ONE AN        - One answer provided");
    println!("  MULTIPLE AN's - Multiple answers");
    println!("  ONE NS        - One authority record");
    println!("  MULTIPLE NS's - Multiple authority records");
    println!("  SOURCE        - Source prefix honored");
    println!("  SCOPE         - Scope prefix honored");
    println!("  ECS           - EDNS Client Subnet extension was present");
    println!("  TTL=X         - Time To Live value for the response");
}

pub fn get_args() -> (String, bool) {
    let args: Vec<String> = env::args().collect();

    // If exactly one argument and it's a help flag, show usage
    if args.len() == 2 && (args[1] == "--help" || args[1] == "-h") {
        print_usage();
        std::process::exit(0);
    }

    // If no arguments (just program name) or too many arguments, show usage
    if args.len() < 2 || args.len() > 3 {
        eprintln!("Error: Invalid number of arguments");
        print_usage();
        std::process::exit(1);
    }

    // First argument should not start with "-"
    if args[1].starts_with("-") {
        eprintln!("Error: First argument must be a short_edge identifier, not a flag");
        print_usage();
        std::process::exit(1);
    }

    let short_edge = args[1].clone();

    // If there's a third argument, validate it's one of the allowed flags
    let verbose = if args.len() == 3 {
        if args[2] == "-v" || args[2] == "--verbose" {
            true
        } else if args[2] == "-h" || args[2] == "--help" {
            eprintln!("Error: Help flag must be used alone");
            print_usage();
            std::process::exit(1);
        } else {
            eprintln!("Error: Unknown flag: {}", args[2]);
            print_usage();
            std::process::exit(1);
        }
    } else {
        false
    };

    (short_edge, verbose)
}

// Helper function to check if an IP is in a subnet
pub fn is_ip_in_subnet(ip: Ipv4Addr, subnet: &str) -> bool {
    let parts: Vec<&str> = subnet.split('/').collect();
    if parts.len() != 2 {
        return false;
    }

    let subnet_ip: Ipv4Addr = match parts[0].parse() {
        Ok(ip) => ip,
        Err(_) => return false,
    };

    let prefix_len: u8 = match parts[1].parse() {
        Ok(len) => len,
        Err(_) => return false,
    };

    if prefix_len > 32 {
        return false;
    }

    let mask = if prefix_len == 0 {
        0
    } else {
        0xFFFFFFFFu32 << (32 - prefix_len)
    };

    let ip_u32 = u32::from(ip);
    let subnet_u32 = u32::from(subnet_ip);

    (ip_u32 & mask) == (subnet_u32 & mask)
}

pub fn find_short_edge_for_ip(ip: Ipv4Addr, ip_to_edge_map: &HashMap<Ipv4Addr, String>, subnet_to_edge_map: &HashMap<String, String>) -> Option<String> {
    // First check direct IP mapping
    if let Some(edge) = ip_to_edge_map.get(&ip) {
        return Some(edge.clone());
    }

    // Then check subnet mapping
    for (subnet, edge) in subnet_to_edge_map {
        if is_ip_in_subnet(ip, subnet) {
            return Some(edge.clone());
        }
    }

    None
}

pub fn display_results(results: &[(String, Ipv4Addr, Option<String>, Vec<String>)], verbose: bool) {
    println!("--- Results ---");
    println!("----------------------------------------------");
    let max_subnet_len = results.iter().map(|(s, _, _, _)| s.len()).max().unwrap_or(0);

    if verbose {
        println!(" {:<max_subnet_len$} - {:<15} - {:<15} - {}", "Tested Subnet", "Result IP", "Result Edge", "Flags");

        for (subnet, ip, edge, flags) in results {
            let edge_str = edge.as_deref().unwrap_or("UNKNOWN");
            println!(" {:<max_subnet_len$} - {:<15} - {:<15} - {}", subnet, ip, edge_str, flags.join(", "));
        }
    } else {
        println!(" {:<max_subnet_len$} - {:<15} - {}", "Tested Subnet", "Result IP", "Result Edge");

        for (subnet, ip, edge, _) in results {
            let edge_str = edge.as_deref().unwrap_or("UNKNOWN");
            println!(" {:<max_subnet_len$} - {:<15} - {}", subnet, ip, edge_str);
        }
    }
}
