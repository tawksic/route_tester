// DNS Header
pub const FLAGS_RD: u16 = 1 << 8;
pub const QDCOUNT_1: u16 = 1;
pub const TYPE_A: u16 = 1;
pub const CLASS_IN: u16 = 1;
pub const ADD_RR: u16 = 1;
pub const ZERO: u16 = 0;

// DNS Flags
pub const FLAG_QR: u16 = 1 << 15;
pub const OPCODE_MASK: u16 = 0x7800; // Bits 11–14
pub const OPCODE_SHIFT: u8 = 11;
pub const FLAG_AA: u16 = 1 << 10;
pub const FLAG_TC: u16 = 1 << 9;
pub const FLAG_RA: u16 = 1 << 7;
pub const RC_MASK: u16 = 0x000F; // Bits 0-3

// EDNS/ECS
pub const ROOT: u8 = 0;
pub const OPT_TYPE: u16 = 41;
pub const UDP_PAYLOAD_SIZE: u16 = 4096;
pub const EXT_RCODE_FLAGS: u32 = 0;
pub const RDLENGTH: u16 = 12;
pub const ECS_OPTION_CODE: u16 = 8;
pub const ECS_OPTION_LEN: u16 = 7;
pub const FAMILY_IPV4: u16 = 1;
pub const SOURCE_PREFIX: u8 = 24;
pub const SCOPE_PREFIX: u8 = 0;
