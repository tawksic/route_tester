use std::net::TcpStream;
use std::net::Ipv4Addr;
use std::collections::HashMap;

use route_tester::database;
use route_tester::dns;
use route_tester::cli;

fn main() -> std::io::Result<()> {
    let (arg_query, verbose) = cli::get_args();

    let db_ip = route_tester::utils::get_secret_ip("db_ip")
        .expect("Failed to get db_ip from secrets");
    let db_port = route_tester::utils::get_secret_int("db_port")
        .expect("Failed to get db_port from secrets");

    let db_addr = format!("{}:{}", db_ip, db_port);
    let mut stream = TcpStream::connect(&db_addr)?;
    let mut auth_state = route_tester::database::AuthState::Initial;
    database::connect_db(&mut auth_state, &mut stream).expect("Failed to connect to fake SNM");

    // Query for the specific short_edge to get subnets to test
    let rows = database::query_db(&arg_query, &mut stream)?;

    // Query for ALL routes to build the mapping
    let all_routes = database::query_all_routes(&mut stream)?;

    // Build mapping structures (to see what edge the Result IP falls under according to fake snm db)
    let mut subnet_to_edge_map: HashMap<String, String> = HashMap::new();
    let mut ip_to_edge_map: HashMap<Ipv4Addr, String> = HashMap::new();

    for (short_edge, subnet) in &all_routes {
        subnet_to_edge_map.insert(subnet.clone(), short_edge.clone());

        if let Ok(ip) = subnet.parse::<Ipv4Addr>() {
            ip_to_edge_map.insert(ip, short_edge.clone());

        }
    }

    // Collect results for each subnet
    let mut results: Vec<(String, Ipv4Addr, Option<String>, Vec<String>)> = Vec::new();

    for (_, subnet) in &rows {
        // Extract first 3 octets from subnet
        let first_3_octets = dns::extract_first_three_octets(subnet);

        // Create DNS packet with this subnet
        let dns_header = dns::create_dh();
        let dns_question = dns::create_dq();
        let opt_record = dns::create_opt_record(first_3_octets);

        let enc_dh = dns::encode_dh(&dns_header);
        let enc_dq = dns::encode_dq(&dns_question);
        let enc_edns = dns::enc_edns(&opt_record);

        let pkt_recvd = match dns::wire(&enc_dh, &enc_dq, &enc_edns) {
            Ok(p) => p,
            Err(e) => {
                println!("Error for subnet {}: {}", subnet, e);
                continue;
            }
        };

        // Length of Header + Question + 12 bytes into the Answer for RDATA
        let enc_dh_len = enc_dh.len();
        let enc_dq_len = enc_dq.len();
        let skip_to_ans = enc_dh_len + enc_dq_len + 12;

        // Skipping domain header + domain question (len) + 4 bytes for RDATA len.. to get to the RDATA (answer)
        if skip_to_ans + 4 <= pkt_recvd.len() {
            let prsd_rdata_ip: [u8; 4] = pkt_recvd[skip_to_ans..skip_to_ans + 4].try_into().unwrap();
            let ip = Ipv4Addr::from(prsd_rdata_ip);

            // Find the corresponding short_edge for this IP
            let result_edge = cli::find_short_edge_for_ip(ip, &ip_to_edge_map, &subnet_to_edge_map);

            // Parse flags if verbose mode is enabled
            let flags = if verbose {
                dns::parse_flags(&pkt_recvd, &dns_header)
            } else {
                Vec::new()
            };

            // Store the result
            results.push((subnet.clone(), ip, result_edge, flags));
        } else {
            println!("Invalid packet received for subnet {}", subnet);
        }
    }

    // Display the results
    cli::display_results(&results, verbose);

    Ok(())
}
