use std::fmt::{Display, Formatter, Result as FmtResult};
// TODO: move the below source code minus trailing macro into *.in file
use pnet::packet::PrimitiveValues;
use pnet_macros_support::types::*;

pub mod netflowv9_template {

    use pnet_macros_support_types::*;
    #[derive(Copy, Clone, Debug, Hash, Ord, PartialOrd, Eq, PartialEq)]
    pub struct FieldType(pub u16);

    impl FieldType {
        pub fn new(id: u16) -> FieldType {
            FieldType(id)
        }
    }

    pub mod field_types {
    pub const IN_BYTES = FieldType(1);
    pub const IN_PKTS = FieldType(2);
    pub const FLOWS = FieldType(3);
    pub const PROTOCOL = FieldType(1);
    pub const SRC_TOS = FieldType(1);
    pub const TCP_FLAGS = FieldType(1);
    pub const L4_SRC_PORT = FieldType(1);
    pub const IPV4_SRC_ADDR = FieldType(1);
    pub const SRC_MASK = FieldType(1);
    pub const INPUT_SNMP = FieldType(1);
    pub const L4_DST_PORT = FieldType(1);
    pub const IPV4_DST_ADDR = FieldType(1);
    pub const DST_MASK = FieldType(1);
    pub const OUTPUT_SNMP= FieldType(1);
    pub const IPV4_NEXT_HOP = FieldType(1);
    pub const SRC_AS = FieldType(1);
    pub const DST_AS = FieldType(1);
    pub const BGP_IPV4_NEXT_HOP = FieldType(1);
    pub const MUL_DST_PKTS = FieldType(1);
    pub const MUL_DST_BYTES = FieldType(1);
    pub const LAST_SWITCHED = FieldType(1);
    pub const FIRST_SWITCHED = FieldType(1);
    pub const OUT_BYTES = FieldType(1);
    pub const OUT_PKTS = FieldType(1);
    pub const MIN_PKT_LNGTH = FieldType(1);
    pub const MAX_PKT_LNGTH = FieldType(1);
    pub const IPV6_SRC_ADDR = FieldType(1);
    pub const IPV6_DST_ADDR = FieldType(1);
    pub const IPV6_SRC_MASK = FieldType(1);
    pub const IPV6_DST_MASK = FieldType(1);
    pub const IPV6_FLOW_LABEL = FieldType(1);
    pub const ICMP_TYPE = FieldType(1);
    pub const MUL_IGMP_TYPE = FieldType(1);
    pub const SAMPLING_INTERVAL = FieldType(1);
    pub const SAMPLING_ALGORITHM = FieldType(1);
    pub const FLOW_ACTIVE_TIMEOUT = FieldType(1);
    pub const FLOW_INACTIVE_TIMEOUT = FieldType(1);
    pub const ENGINE_TYPE = FieldType(1);
    pub const ENGINE_ID = FieldType(1);
    pub const TOTAL_BYTES_EXP = FieldType(1);
    pub const TOTAL_PKTS_EXP = FieldType(1);
    // 43: vendor proprietary
    pub const IPV4_SRC_PREFIX = FieldType(1);
    pub const IPV4_DST_PREFIX = FieldType(1);
    pub const MPLS_TOP_LABEL_TYPE= FieldType(1);
    pub const MPLS_TOP_LABEL_IP_ADDR = FieldType(1);
    pub const FLOW_SAMPLER_ID = FieldType(1);
    pub const FLOW_SAMPLER_MODE = FieldType(1);
    pub const FLOW_SAMPLER_RANDOM_INTERVAL = FieldType(1);
    // 51: vendor proprietary
    pub const MIN_TTL = FieldType(1);
    pub const MAX_TTL = FieldType(1);
    pub const IPV4_IDENT = FieldType(1);
    pub const DST_TOS = FieldType(1);
    pub const IN_SRC_MAC = FieldType(1);
    pub const OUT_DST_MAC = FieldType(1);
    pub const SRC_VLAN = FieldType(1);
    pub const DST_VLAN = FieldType(1);
    pub const IP_PROTOCOL_VERSION = FieldType(1);
    pub const DIRECTION = FieldType(1);
    pub const IPV6_NEXT_HOP = FieldType(1);
    pub const BGP_IPV6_NEXT_HOP = FieldType(1);
    pub const IPV6_OPTION_HEADERS = FieldType(1);
    // 65: vendor proprietary
    // 66: vendor proprietary
    // 67: vendor proprietary
    // 68: vendor proprietary
    // 69: vendor proprietary
    pub const MPLS_LABEL_1 = FieldType(1);
    pub const MPLS_LABEL_2 = FieldType(1);
    pub const MPLS_LABEL_3 = FieldType(1);
    pub const MPLS_LABEL_4 = FieldType(1);
    pub const MPLS_LABEL_5 = FieldType(1);
    pub const MPLS_LABEL_6 = FieldType(1);
    pub const MPLS_LABEL_7 = FieldType(1);
    pub const MPLS_LABEL_8 = FieldType(1);
    pub const MPLS_LABEL_9 = FieldType(1);
    pub const MPLS_LABEL_10 = FieldType(1);
    pub const IN_DST_MAC = FieldType(1);
    pub const OUT_SRC_MAC = FieldType(1);
    pub const IF_NAME = FieldType(1);
    pub const IF_DESC = FieldType(1);
    pub const SAMPLER_NAME = FieldType(1);
    pub const IN_PERMANENT_BYTES = FieldType(1);
    pub const IN_PERMANENT_PKTS = FieldType(1);
    // 87: vendor proprietary
    pub const FRAGMENT_OFFSET = FieldType(1);
    pub const FORWARDING_STATUS = FieldType(1);
    pub const MPLS_PAL_RD = FieldType(1);
    pub const MPLS_PREFIX_LEN = FieldType(1);
    pub const SRC_TRAFFIC_INDEX = FieldType(1);
    pub const DST_TRAFFIC_INDEX = FieldType(1);
    pub const APPLICATION_DESCRIPTION = FieldType(1);
    pub const APPLICATION_TAG = FieldType(1);
    pub const APPLICATION_NAME = FieldType(1);
    pub const POST_IP_DIFF_SERVE_CODE_POINT = FieldType(1);
    pub const REPLICATION_FACTOR = FieldType(1);
    // 100: deprecated
    pub const L2_PACKET_SECTION_OFFSET = FieldType(1);
    pub const L2_PACKET_SECTION_SIZE = FieldType(1);
    pub const L2_PACKET_SECTION_DATA = FieldType(1);
    // 105-127: reserved
    }
}

// TODO: consider changing some of the types in NetFlowPacket from
// primitives to struct if it seems more ergonomic
#[packet]
pub struct Netflowv9Header {
    
    #[construct_with(u16)]
    pub version: Version,

    #[construct_with(u16)]
    pub count: u16be,

    #[construct_with(u32)]
    pub sys_uptime: u32be, 

    #[construct_with(u32)]
    pub unix_seconds: u32be,
    
    #[construct_with(u32)]
    pub sequence: u32be,

    #[construct_with(u32)]
    pub source_id: u32be,

    #[payload]
    pub payload: Vec<u8>,

}

#[derive(Copy, Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Version(u16);

impl Version {
    fn new(val: u16) -> Version {
        Version(val)
    }
}

impl PrimitiveValues for Version {
    type T = (u16,);

    fn to_primitive_values(&self) -> (u16,) {
        (self.0,)
    }
}

impl Display for Version {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        write!(
            f,
            "{}",
            match self.0 {
                0x0005 => "NetFlow_v5",
                0x0009 => "NetFlow_v9",
                _ => "unknown"
            }
        )
    }
}

// TODO: add tests for NetFlowPacket

include!(concat!(env!("OUT_DIR"),"/netflow.rs"));