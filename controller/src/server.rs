pub mod c2_protocol;
pub mod c2_state;
pub mod cli;
pub mod dns;
pub mod encoding;

pub use c2_protocol::{parse_c2_request, C2Request};
pub use c2_state::C2State;
pub use cli::{cli_loop, print_banner, print_help};
pub use dns::{
    build_a_record_response, build_txt_record_response, parse_domain_name, parse_question,
    DnsHeader, DnsQuestion, QType,
};
pub use encoding::base64_encode;
