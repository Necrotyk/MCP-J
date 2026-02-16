#![no_main]
use libfuzzer_sys::fuzz_target;
use mcp_j_proxy::JsonRpcProxy;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        let proxy = JsonRpcProxy::new(None);
        let _ = proxy.validate_and_parse(s);

        // Deeply nested JSON injection
        let nested = format!("{}{}{}", "[".repeat(500), s, "]".repeat(500));
        let _ = proxy.validate_and_parse(&nested);
    }
});
