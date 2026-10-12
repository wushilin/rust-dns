//! Live DNSSEC smoke check for the real `wushilin.net` zone.
//!
//! Google Public DNS performs DNSSEC validation while resolving over HTTPS.
//! Its authenticated-data (AD) flag confirms the response validated through
//! the resolver's root trust anchor, without requiring local DNS tools.

#[test]
fn wushilin_net_dnskey_is_dnssec_validated() {
    let response = ureq::AgentBuilder::new()
        .timeout(std::time::Duration::from_secs(20))
        .build()
        .get("https://dns.google/resolve?name=wushilin.net.&type=DNSKEY&do=1")
        .call()
        .expect("query Google Public DNS over HTTPS")
        .into_json::<serde_json::Value>()
        .expect("parse Google Public DNS JSON response");

    assert!(
        response["Status"].as_u64() == Some(0),
        "Google Public DNS returned a DNS error: {response}"
    );
    assert!(
        response["AD"].as_bool() == Some(true),
        "Google Public DNS did not authenticate the wushilin.net DNSKEY response: {response}"
    );
    let answers = response["Answer"]
        .as_array()
        .expect("DNSKEY answer section");
    assert!(
        answers
            .iter()
            .any(|answer| answer["type"].as_u64() == Some(48)),
        "response contains no DNSKEY records: {response}"
    );
    assert!(
        answers
            .iter()
            .any(|answer| answer["type"].as_u64() == Some(46)),
        "DO=1 response contains no RRSIG records: {response}"
    );
}
