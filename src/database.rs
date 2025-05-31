use std::net::TcpStream;
use std::io::{BufRead, Write};
use std::ffi::CString;

// From crates - I cheated because encryption is insane
use hmac::Hmac;
use hmac::Mac;
use sha2::Digest;
use sha2::Sha256;
use pbkdf2::pbkdf2;
use base64::engine::general_purpose::STANDARD as base64_std;
use base64::Engine;

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug)]
pub enum AuthState {
    Initial,
    SASLStarted,
    SASLContinue(String),
    SASLFinal,
    Authenticated,
    Error(String)
}

struct StartupMessage {
    msg_len: u32,
    proto_vers: u32,
    user_key: CString,
    user_val: CString,
    database_key: CString,
    database_val: CString,
    end: u8
}

struct SASLInitialResponse {
    resp_type: u8,
    msg_len: u32,
    auth_mech: CString,
    auth_len: u32,
    client_first_msg: Vec<u8>
}

struct Query {
    resp_type: u8,
    msg_len: u32,
    query: CString
}

fn wire(message: &[u8], stream: &mut TcpStream) -> std::io::Result<Vec<u8>> {

    stream.write_all(message)?;
    stream.flush()?;

    let mut reader = std::io::BufReader::new(stream);
    let received: Vec<u8> = reader.fill_buf()?.to_vec();
    reader.consume(received.len());

    Ok(received)
}

fn create_start_message() ->  StartupMessage {
    let user_key = CString::new("user").unwrap();
    let db_user = crate::utils::get_secret_string("db_user")
        .expect("Failed to get db_user from secrets");
    let user_val = CString::new(db_user).unwrap();

    let database_key = CString::new("database").unwrap();
    let db_name = crate::utils::get_secret_string("db_name")
        .expect("Failed to get db_name from secrets");
    let database_val = CString::new(db_name).unwrap();

    // Calculate the total message length
    let msg_len = 4 // msg_len
                + 4 // proto_vers
                + user_key.as_bytes_with_nul().to_vec().len()
                + user_val.as_bytes_with_nul().to_vec().len()
                + database_key.as_bytes_with_nul().to_vec().len()
                + database_val.as_bytes_with_nul().to_vec().len()
                + 1; // end


    let start_message = StartupMessage {
        msg_len: msg_len as u32,
        proto_vers: (3 << 16), // bitshifting because Postgres designates major version in first 16 bits, minor in last 16 bits AKA 3.0
        user_key: user_key,
        user_val: user_val,
        database_key: database_key,
        database_val: database_val,
        end: 0,
    };

    start_message
}

fn encode_start_msg(start_message: &StartupMessage) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(&start_message.msg_len.to_be_bytes());
    buf.extend_from_slice(&start_message.proto_vers.to_be_bytes());
    buf.extend_from_slice(start_message.user_key.as_bytes_with_nul());
    buf.extend_from_slice(start_message.user_val.as_bytes_with_nul());
    buf.extend_from_slice(start_message.database_key.as_bytes_with_nul());
    buf.extend_from_slice(start_message.database_val.as_bytes_with_nul());
    buf.push(start_message.end);

    buf
}

fn create_sasl_initial_response() -> SASLInitialResponse {
    // Create client_first_msg
    let nonce = crate::utils::rand();
    let db_user = crate::utils::get_secret_string("db_user")
        .expect("Failed to get db_user from secrets");
    let client_first_msg = format!("n,,n={},r={}", db_user, nonce);
    let client_first_msg_bytes = client_first_msg.as_bytes().to_vec();
    let auth_len = client_first_msg_bytes.len() as u32;

    // Create auth_mech
    let auth_mech = CString::new("SCRAM-SHA-256").unwrap();
    let auth_mech_bytes = auth_mech.as_bytes_with_nul().to_vec();

    // Calculate the total message length
    let msg_len = 4                      // msg_len
                + auth_mech_bytes.len()  // auth_mech
                + 4                      // auth_len
                + auth_len as usize;     // client_first_msg

    let sasl_initial_response = SASLInitialResponse {
        resp_type: b'p',
        msg_len: msg_len as u32,
        auth_mech: auth_mech,
        auth_len: auth_len,
        client_first_msg: client_first_msg_bytes,
    };

    sasl_initial_response
}

fn encode_sasl_response(message: &str) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.push(b'p');
    let msg_bytes = message.as_bytes();
    let len = 4 + msg_bytes.len();
    buf.extend_from_slice(&(len as u32).to_be_bytes());
    buf.extend_from_slice(msg_bytes);
    buf
}

fn encode_sasl_initial_response(resp: &SASLInitialResponse) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.push(resp.resp_type);
    buf.extend_from_slice(&resp.msg_len.to_be_bytes());
    buf.extend_from_slice(resp.auth_mech.as_bytes_with_nul());
    buf.extend_from_slice(&resp.auth_len.to_be_bytes());
    buf.extend_from_slice(&resp.client_first_msg);

    buf
}

fn create_query(arg_query: &String) -> Query {
    let formated_query = format!("SELECT short_edge, subnet FROM routes WHERE short_edge = '{}';", arg_query);
    let query = CString::new(formated_query).expect("Failed to create CString");
    let msg_len = 4 + query.as_bytes_with_nul().len();

    Query {
        resp_type: b'Q',
        msg_len: msg_len as u32,
        query,
    }
}

fn create_query_all_routes() -> Query {
    let formated_query = format!("SELECT short_edge, subnet FROM routes;");
    let query = CString::new(formated_query).expect("Failed to create CString");
    let msg_len = 4 + query.as_bytes_with_nul().len();

    Query {
        resp_type: b'Q',
        msg_len: msg_len as u32,
        query,
    }
}

fn encode_query(query: &Query) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(&query.resp_type.to_be_bytes());
    buf.extend_from_slice(&query.msg_len.to_be_bytes());
    buf.extend_from_slice(&query.query.as_bytes_with_nul());

    buf
}

fn salted_password(password: &str, base64_salt: &str, iterations: u32) -> [u8; 32] {
    let salt = base64_std.decode(base64_salt).expect("invalid base64");
    let mut output = [0u8; 32];
    let _ = pbkdf2::<HmacSha256>(password.as_bytes(), &salt, iterations, &mut output);
    output
}

fn client_key(salted_password: &[u8]) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(salted_password).unwrap();
    mac.update(b"Client Key");
    let result = mac.finalize().into_bytes();
    result.into()
}

fn stored_key(client_key: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(client_key);
    hasher.finalize().into()
}

fn client_signature(stored_key: &[u8], auth_message: &[u8]) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(stored_key).unwrap();
    mac.update(auth_message);
    mac.finalize().into_bytes().into()
}

fn client_proof(client_key: &[u8], client_signature: &[u8]) -> Vec<u8> {
    client_key.iter()
        .zip(client_signature)
        .map(|(a, b)| a ^ b)
        .collect()
}

fn calculate_sasl_final(server_first_msg: &str, sasl_initial_response: &SASLInitialResponse) -> String {
    // Variables to store SCRAM values sent by server
    let mut nonce = "";       // r=<nonce>
    let mut salt = "";        // s=<base64-salt>
    let mut iterations = 0;   // i=<iteration-count>

    // Split the server message into fields and extract relevant SCRAM parts
    for part in server_first_msg.split(',') {
        if part.starts_with("r=") {
            nonce = &part[2..];
        } else if part.starts_with("s=") {
            salt = &part[2..];
        } else if part.starts_with("i=") {
            iterations = part[2..].parse::<u32>().unwrap();
        }
    }

    // Reconstruct the client-first-message-bare (everything after "n,,")
    let client_first_bare = std::str::from_utf8(&sasl_initial_response.client_first_msg[3..]).unwrap();

    // Construct the client-final-message (without proof yet)
    let client_final_wo_proof = format!("c=biws,r={}", nonce);

    // The auth_message is a concatenation of three parts:
    let auth_message = format!("{},{},{}", client_first_bare, server_first_msg, client_final_wo_proof);

    // Derive SCRAM secrets
    let db_pass = crate::utils::get_secret_string("db_pass")
        .expect("Failed to get db_pass from secrets");
    let salted = salted_password(&db_pass, salt, iterations);
    let ck = client_key(&salted);
    let sk = stored_key(&ck);
    let sig = client_signature(&sk, auth_message.as_bytes());
    let proof = client_proof(&ck, &sig);
    let proof_b64 = base64_std.encode(&proof);

    format!("{},p={}", client_final_wo_proof, proof_b64)
}

fn get_err_msg(message: &[u8]) -> String {
    // E stands for Error in Postgres ErrorResponse messages
    let message_content = message[5..].to_vec();
    let msg_iter = message_content.split(|end| *end == 0);

    for element in msg_iter {
        // M stands for Message in Postgres ErrorResponse messages
        if !element.is_empty() && element[0] == b'M' {
            return std::str::from_utf8(&element[1..]).unwrap().to_string()
            // return error_msg
        }
    }
    // Should never hit this final panic per the Postgres ErrorResponse specs
    panic!("Received ErrorResponse, but no message ('M') field found");
}

// Parse function returns just the new state with any needed data
fn parse_auth_response(message: &[u8], current_state: &AuthState) -> AuthState {
    let resp_type = message[0];

    // E = Error, Z = ReadyForQuery, R = Response
    // https://www.postgresql.org/docs/current/protocol-message-formats.html

    if resp_type == b'E' {
        return AuthState::Error(get_err_msg(message));
    }

    if resp_type == b'Z' {
        return AuthState::Authenticated;
    }

    if resp_type != b'R' {
        return AuthState::Error(format!("Expected auth response (R), got: {}", resp_type as char));
    }

    // Auth code is at bytes 5-8
    let auth_code = u32::from_be_bytes([
        message[5], message[6], message[7], message[8]
    ]);

    match (current_state, auth_code) {
        (AuthState::Initial, 10) => AuthState::SASLStarted,
        (AuthState::SASLStarted, 11) => {
            let msg_len = u32::from_be_bytes([message[1], message[2], message[3], message[4]]) as usize;
            let server_first_msg_bytes = &message[9..(1 + msg_len)];
            let server_first_msg = match std::str::from_utf8(server_first_msg_bytes) {
                Ok(msg) => msg.to_string(),
                Err(e) => return AuthState::Error(format!("Invalid UTF-8 in server message: {}", e)),
            };
            AuthState::SASLContinue(server_first_msg)
        },
        (AuthState::SASLContinue(_), 12) => AuthState::SASLFinal,
        (AuthState::SASLContinue(_), 0) | (AuthState::SASLFinal, 0) => AuthState::Authenticated,
        _ => AuthState::Error(format!("Unexpected auth code {} in state {:?}", auth_code, current_state))
    }
}

fn fetch_rows(message: &Vec<u8>) -> Vec<(String, String)> {
    let mut responses = Vec::new();
    let mut i = 0;

    while i < message.len() {
        let msg_type = message[i];

        // Read message length (4 bytes after type)
        if i + 4 >= message.len() {
            break;
        }

        let msg_len = u32::from_be_bytes([
            message[i + 1], message[i + 2], message[i + 3], message[i + 4],
        ]) as usize;

        if i + 1 + msg_len > message.len() {
            break;
        }

        if msg_type == b'D' {
            // number of columns (2 bytes)
            let field_count = u16::from_be_bytes([
                message[i + 5],
                message[i + 6],
            ]) as usize;

            let mut fields: Vec<String> = Vec::with_capacity(field_count);
            // skip type field (1), msg len (4), num of cols (2) = 7
            let mut cursor = i + 7;

            for _ in 0..field_count {
                let field_len = u32::from_be_bytes([
                    message[cursor],
                    message[cursor + 1],
                    message[cursor + 2],
                    message[cursor + 3],
                ]) as usize;
                cursor += 4;

                let field_data = &message[cursor..cursor + field_len];
                let field_str = std::str::from_utf8(field_data).unwrap().to_string();

                fields.push(field_str);

                cursor += field_len;
            }

            let (short_edge, subnet) = (fields.remove(0), fields.remove(0));

            responses.push((short_edge, subnet));
        }

        i += msg_len + 1; // move to next message
    }

    responses
}



pub fn connect_db(auth_state: &mut AuthState, mut stream: &mut TcpStream) -> std::io::Result<()> {
    // Step 1: StartupMessage
    let start_message = create_start_message();
    let encoded_start_msg = encode_start_msg(&start_message);
    let recv_start_msg = wire(&encoded_start_msg, &mut stream)?;
    let mut auth_state = parse_auth_response(&recv_start_msg, &auth_state);

    // Step 2: SASL Initial Response
    if let AuthState::SASLStarted = auth_state {
        let sasl_initial_response = create_sasl_initial_response();
        let enc_sasl_initial_response = encode_sasl_initial_response(&sasl_initial_response);
        let recv_sasl_initial_response = wire(&enc_sasl_initial_response, &mut stream)?;
        auth_state = parse_auth_response(&recv_sasl_initial_response, &auth_state);

        // Step 3: SASL Continue Response
        if let AuthState::SASLContinue(ref server_first_msg) = auth_state {
            let sasl_final_response = calculate_sasl_final(server_first_msg, &sasl_initial_response);
            let enc_sasl_final_response = encode_sasl_response(&sasl_final_response);
            let recv_final_response = wire(&enc_sasl_final_response, &mut stream)?;

            // Loop through all messages in this buffer
            let mut i = 0;
            while i < recv_final_response.len() {
                let _ = recv_final_response[i];
                let len = u32::from_be_bytes([
                    recv_final_response[i + 1],
                    recv_final_response[i + 2],
                    recv_final_response[i + 3],
                    recv_final_response[i + 4],
                ]) as usize;

                let msg = &recv_final_response[i..i + len + 1]; // +1 for msg type byte
                auth_state = parse_auth_response(msg, &auth_state);

                i += len + 1;
            }
        }
    }

    // Check final auth state
    match auth_state {
        AuthState::Authenticated => (),
        AuthState::Error(ref msg) => panic!("Authentication failed: {}", msg),
        _ => panic!("Unexpected auth state: {:?}", auth_state),
    }

    // Step 4: Execute Query
    Ok(())
}

pub fn query_db(arg_query: &String, stream: &mut TcpStream) -> std::io::Result<Vec<(String, String)>> {
    let query = create_query(arg_query);
    let enc_query = encode_query(&query);
    let recv_enc_query = wire(&enc_query, stream)?;

    if recv_enc_query[0] == b'E' {
        panic!("Query error: {}", get_err_msg(&recv_enc_query));
    }

    let rows = fetch_rows(&recv_enc_query);

    Ok(rows)
}

pub fn query_all_routes(stream: &mut TcpStream) -> std::io::Result<Vec<(String, String)>> {
    let query = create_query_all_routes();
    let enc_query = encode_query(&query);
    let recv_enc_query = wire(&enc_query, stream)?;

    if recv_enc_query[0] == b'E' {
        panic!("Query error: {}", get_err_msg(&recv_enc_query));
    }

    let rows = fetch_rows(&recv_enc_query);

    Ok(rows)
}
