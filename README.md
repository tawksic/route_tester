# Route Tester

## About
This was a personal project where I ported a script I wrote in Golang to Rust. It's my first "finished" project in Rust and was created for the purpose of learning Rust.

What the tool does is queries a Postgres database based (hosted on a personal VPS) on an edge server name and spits out all the subnets that edge has associated with it. It will then send a dns request (ECS enabled) for a specified target using a specified resolver and returns the resulting IP and the edge that it maps to in the database.

I gave myself the added challenge of not using any Crates (no third party code such as dns libraries or database libraries). This meant manually translating requests and responses to bytes and sending/receiving them via TCP sockets for Postgres and UDP sockets for DNS requests, by hand. This also meant manual SCRAM authentication with Postgres. I did cheat and use Crates for encryption, because crypto is insane.

## Getting started
```
# Install Rust
$ brew install rust

# Verify Rust and Cargo (Rusts built in package manager) work
$ rustc --version
$ cargo --version
```

## Clone the repo and ask for the credentials
```
$ git clone https://github.com/tawksic/route_tester.git
$ cd route_tester
$ touch .secrets.yaml # Add the credentials here
```

## Usage
```
# Build it - This will create an executable in ./target/debug/route_tester
$ cargo build

# Help
$ ./target/debug/route_tester -h
Usage: route_tester <short_edge> [OPTIONS]
Options:
  -v, --verbose    Display detailed DNS response flags
  -h, --help       Display this help message

Verbose mode flags (True if displayed):
  RESP          - This is a response
  SQ            - Standard query
  AA            - Authoritative Answer
  TC            - Truncated response
  REC           - Recursion provided
  MATCH         - ID matched the request
  ONE AN        - One answer provided
  MULTIPLE AN's - Multiple answers
  ONE NS        - One authority record
  MULTIPLE NS's - Multiple authority records
  SOURCE        - Source prefix honored
  SCOPE         - Scope prefix honored
  ECS           - EDNS Client Subnet extension was present
  TTL=X         - Time To Live value for the response

# Example:
$ cargo run --quiet -- ef-co-elin01
--- Results ---
----------------------------------------------
 Tested Subnet    - Result IP       - Result Edge
 170.10.64.0/24   - 170.10.64.162   - ef-co-elin01
 170.10.65.0/24   - 170.10.64.162   - ef-co-elin01
 192.139.255.0/24 - 170.10.64.162   - ef-co-elin01
```
