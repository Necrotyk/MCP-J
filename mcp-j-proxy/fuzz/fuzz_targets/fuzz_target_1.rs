#![no_main]
use libfuzzer_sys::fuzz_target;
use mcp_j_proxy::JsonRpcProxy;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        let proxy = JsonRpcProxy::new();
        let _ = proxy.validate_and_parse(s);
    }
});
