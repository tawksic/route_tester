use std::net::UdpSocket;
use std::time::Duration;

pub struct DnsHeader {
    pub id: u16,
    pub flags: u16,
    pub num_questions: u16,
    pub num_answers: u16,
    pub num_authorities: u16,
    pub num_additionals: u16,
}

pub struct DnsQuestion {
    pub name: String,
    pub type_: u16,
    pub class: u16,
}

pub struct OptRecord {
    pub name: u8,
    pub type_: u16,
    pub udp_size: u16,
    pub ext_rcode_flags: u32,
    pub option_code: u16,
    pub option_len: u16,
    pub family: u16,
    pub source_prefix: u8,
    pub scope_prefix: u8,
    pub address: [u8; 3],
}

pub fn create_dh() -> DnsHeader {
    let dns_header = DnsHeader {
        id: crate::utils::rand(),
        flags: crate::dns_consts::FLAGS_RD,
        num_questions: crate::dns_consts::QDCOUNT_1,
        num_answers: crate::dns_consts::ZERO,
        num_authorities: crate::dns_consts::ZERO,
        num_additionals: crate::dns_consts::ADD_RR,
    };

    dns_header
}

pub fn encode_dh(dns_header: &DnsHeader) -> Vec<u8> {
    let mut buf: Vec<u8> = Vec::new();
    buf.extend_from_slice(&dns_header.id.to_be_bytes());
    buf.extend_from_slice(&dns_header.flags.to_be_bytes());
    buf.extend_from_slice(&dns_header.num_questions.to_be_bytes());
    buf.extend_from_slice(&dns_header.num_answers.to_be_bytes());
    buf.extend_from_slice(&dns_header.num_authorities.to_be_bytes());
    buf.extend_from_slice(&dns_header.num_additionals.to_be_bytes());

    buf
}

pub fn create_dq() -> DnsQuestion {
    let net_target = crate::utils::get_secret_string("net_target")
        .expect("Failed to get net_target from secrets");

    let dns_question = DnsQuestion {
        name: net_target,
        type_: crate::dns_consts::TYPE_A,
        class: crate::dns_consts::CLASS_IN,
    };

    dns_question
}

pub fn encode_dq(dns_question: &DnsQuestion) -> Vec<u8> {
    let enc_name = encode_dq_name(&dns_question);

    let mut buf: Vec<u8> = Vec::new();
    buf.extend_from_slice(&enc_name);
    buf.extend_from_slice(&dns_question.type_.to_be_bytes());
    buf.extend_from_slice(&dns_question.class.to_be_bytes());

    buf
}

pub fn encode_dq_name(dns_question: &DnsQuestion) -> Vec<u8> {
    let name_iter = dns_question.name.split('.');

    let mut buf = Vec::new();

    for iter in name_iter {
        buf.push(iter.len() as u8);
        buf.extend_from_slice(iter.as_bytes());
    };
    buf.push(0);

    buf
}

pub fn create_opt_record(address: [u8; 3]) -> OptRecord {
    let opt_record = OptRecord {
        name: crate::dns_consts::ROOT,
        type_: crate::dns_consts::OPT_TYPE,
        udp_size: crate::dns_consts::UDP_PAYLOAD_SIZE,
        ext_rcode_flags: crate::dns_consts::EXT_RCODE_FLAGS,
        option_code: crate::dns_consts::ECS_OPTION_CODE,
        option_len: crate::dns_consts::ECS_OPTION_LEN,
        family: crate::dns_consts::FAMILY_IPV4,
        source_prefix: crate::dns_consts::SOURCE_PREFIX,
        scope_prefix: crate::dns_consts::SCOPE_PREFIX,
        address: address,
    };

    opt_record
}

pub fn enc_edns(opt_record: &OptRecord) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.push(opt_record.name);
    buf.extend_from_slice(&opt_record.type_.to_be_bytes());
    buf.extend_from_slice(&opt_record.udp_size.to_be_bytes());
    buf.extend_from_slice(&opt_record.ext_rcode_flags.to_be_bytes());

    let ecs_option = encode_ecs_option(opt_record);

    buf.extend_from_slice(&(ecs_option.len() as u16).to_be_bytes());
    buf.extend_from_slice(&ecs_option);

    buf
}

pub fn encode_ecs_option(opt_record: &OptRecord) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(&opt_record.option_code.to_be_bytes());
    buf.extend_from_slice(&opt_record.option_len.to_be_bytes());
    buf.extend_from_slice(&opt_record.family.to_be_bytes());
    buf.push(opt_record.source_prefix);
    buf.push(opt_record.scope_prefix);
    buf.extend_from_slice(&opt_record.address);

    buf
}

pub fn wire(enc_dh: &Vec<u8>, enc_dq: &Vec<u8>, enc_edns: &Vec<u8>) -> Result<Vec<u8>, std::io::Error> {
    let mut send_buf: Vec<u8> = Vec::new();
    send_buf.extend_from_slice(&enc_dh);
    send_buf.extend_from_slice(&enc_dq);
    send_buf.extend_from_slice(&enc_edns);

    let udp_socket = UdpSocket::bind("0.0.0.0:0")?;
    udp_socket.set_read_timeout(Some(Duration::from_secs(5)))?;

    let net_rslvr = crate::utils::get_secret_string("net_rslvr")
        .expect("Failed to get net_rslvr from secrets");
    let net_rslvr_port = crate::utils::get_secret_int("net_rslvr_port")
        .expect("Failed to get net_rslvr_port from secrets");

    let resolver_addr = format!("{}:{}", net_rslvr, net_rslvr_port);
    let _ = udp_socket.send_to(&send_buf.as_slice(), &resolver_addr);

    let mut recv_buf = [0u8; 512];
    let (num_of_bytes, _) = udp_socket
        .recv_from(&mut recv_buf)
        .expect("didnt receive data");
    let filled_buf = &mut recv_buf[..num_of_bytes];

    Ok(filled_buf.to_vec())
}

// This function should take a subnet string like "170.10.64.0/24" and return [170, 10, 64]
pub fn extract_first_three_octets(subnet: &str) -> [u8; 3] {
    let mut octets = [0u8; 3];
    let parts: Vec<&str> = subnet.split('.').collect();

    for i in 0..3 {
        if i < parts.len() {
            octets[i] = parts[i].parse().unwrap_or(0);
        }
    }

    octets
}

pub fn parse_flags(pkt_recvd: &[u8], dns_header: &DnsHeader) -> Vec<String> {
    let mut flags = Vec::new();

    // Parse ID
    let prsd_id: [u8; 2] = pkt_recvd[0..2].try_into().unwrap();
    if dns_header.id == u16::from_be_bytes(prsd_id) {
        flags.push("MATCH".to_string());
    }

    // Parse Flags
    let prsd_flgs: [u8; 2] = pkt_recvd[2..4].try_into().unwrap();
    let prsd_flgs_as_u16 = u16::from_be_bytes(prsd_flgs);

    if (prsd_flgs_as_u16 & crate::dns_consts::FLAG_QR) != 0 {
        flags.push("RESP".to_string());
    }

    let opcode = (prsd_flgs_as_u16 & crate::dns_consts::OPCODE_MASK) >> crate::dns_consts::OPCODE_SHIFT;
    if opcode == 0 {
        flags.push("SQ".to_string());
    }

    if (prsd_flgs_as_u16 & crate::dns_consts::FLAG_AA) != 0 {
        flags.push("AA".to_string());
    }

    if (prsd_flgs_as_u16 & crate::dns_consts::FLAG_TC) != 0 {
        flags.push("TC".to_string());
    }

    if (prsd_flgs_as_u16 & crate::dns_consts::FLAG_RA) != 0 {
        flags.push("REC".to_string());
    }

    // Parse ANCOUNT
    let prsd_ancount: [u8; 2] = pkt_recvd[6..8].try_into().unwrap();
    let prsd_ancount_as_u16: u16 = u16::from_be_bytes(prsd_ancount);
    if prsd_ancount_as_u16 == 1 {
        flags.push("ONE AN".to_string());
    } else if prsd_ancount_as_u16 > 1 {
        flags.push("MULTIPLE AN's".to_string());
    }

    // Parse NSCOUNT
    let prsd_nscount: [u8; 2] = pkt_recvd[8..10].try_into().unwrap();
    let prsd_nscount_as_u16: u16 = u16::from_be_bytes(prsd_nscount);
    if prsd_nscount_as_u16 == 1 {
        flags.push("ONE NS".to_string());
    } else if prsd_nscount_as_u16 > 1 {
        flags.push("MULTIPLE NS's".to_string());
    }

    // Find the OPT record in the additional section
    // Skip over the header (12 bytes)
    let mut offset = 12;

    // Skip over the question
    // First part is the domain name which is variable length
    while offset < pkt_recvd.len() {
        let len = pkt_recvd[offset] as usize;
        if len == 0 {
            offset += 1; // Skip the null terminator
            break;
        }
        offset += len + 1; // Skip label length byte and the label itself
    }

    // Skip over the question's type and class (4 bytes)
    offset += 4;

    // If there are answers, extract TTL from the first answer
    if prsd_ancount_as_u16 > 0 {
        let answer_start = offset;

        // Skip name (could be compressed)
        if (pkt_recvd[offset] & 0xC0) == 0xC0 {
            offset += 2; // Compressed name, 2 bytes
        } else {
            // Uncompressed name, need to skip each label
            while offset < pkt_recvd.len() {
                let len = pkt_recvd[offset] as usize;
                if len == 0 {
                    offset += 1;
                    break;
                }
                offset += len + 1;
            }
        }

        // Skip type, class (4 bytes)
        if offset + 8 < pkt_recvd.len() {
            // TTL is a 32-bit value starting at offset+4
            let ttl_bytes: [u8; 4] = [
                pkt_recvd[offset + 4],
                pkt_recvd[offset + 5],
                pkt_recvd[offset + 6],
                pkt_recvd[offset + 7]
            ];
            let ttl = u32::from_be_bytes(ttl_bytes);
            flags.push(format!("TTL={}", ttl));
        }

        // Reset offset to continue parsing
        offset = answer_start;
    }

    // Skip over any answer records to get to additional section
    for _ in 0..prsd_ancount_as_u16 {
        // Skip name (could be compressed)
        if offset + 2 >= pkt_recvd.len() {
            break;
        }

        if (pkt_recvd[offset] & 0xC0) == 0xC0 {
            offset += 2; // Compressed name, 2 bytes
        } else {
            // Uncompressed name, need to skip each label
            while offset < pkt_recvd.len() {
                let len = pkt_recvd[offset] as usize;
                if len == 0 {
                    offset += 1;
                    break;
                }
                offset += len + 1;
            }
        }

        // Skip type, class, TTL
        offset += 8;

        // Get data length and skip data
        if offset + 2 >= pkt_recvd.len() {
            break;
        }
        let data_len = u16::from_be_bytes([pkt_recvd[offset], pkt_recvd[offset + 1]]) as usize;
        offset += 2 + data_len;
    }

    // Now look for OPT record
    if offset + 10 < pkt_recvd.len() {
        // Check if this is an OPT record
        let opt_type = u16::from_be_bytes([pkt_recvd[offset + 1], pkt_recvd[offset + 2]]);

        if opt_type == crate::dns_consts::OPT_TYPE {
            // Skip to the EDNS0 option data
            offset += 11; // name (1) + type (2) + udp_size (2) + ext_rcode_flags (4) + rdlen (2)

            // Now check for ECS option
            if offset + 4 < pkt_recvd.len() {
                let option_code = u16::from_be_bytes([pkt_recvd[offset], pkt_recvd[offset + 1]]);

                if option_code == crate::dns_consts::ECS_OPTION_CODE {
                    // Add flag that ECS was supplied in the response
                    flags.push("ECS".to_string());

                    // Skip to the ECS option data
                    offset += 4; // Skip option code (2) + option length (2)

                    // Check source prefix and scope prefix
                    if offset + 4 < pkt_recvd.len() {
                        let source_prefix = pkt_recvd[offset + 2];
                        let scope_prefix = pkt_recvd[offset + 3];

                        if source_prefix == crate::dns_consts::SOURCE_PREFIX {
                            flags.push("SOURCE".to_string());
                        }

                        if scope_prefix == 24 {
                            flags.push("SCOPE".to_string());
                        }
                    }
                }
            }
        }
    }

    flags
}
