pub const INDEX_HTML: &str = include_str!("index.html");

/// API explorer page (Swagger UI) served at /rust-dns/docs.
pub const DOCS_HTML: &str = include_str!("docs.html");
/// Vendored Swagger UI assets, stored gzipped (served as-is to clients that
/// accept gzip, which is every browser).
pub const SWAGGER_JS_GZ: &[u8] = include_bytes!("swagger/swagger-ui-bundle.js.gz");
pub const SWAGGER_CSS_GZ: &[u8] = include_bytes!("swagger/swagger-ui.css.gz");
pub const SWAGGER_VERSION: &str = include_str!("swagger/VERSION");

/// Pages served with a document Content-Security-Policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Page {
    Console,
    Docs,
}

/// `'sha256-...'` sources for every inline `<script>` block of `html`.
/// The pages are compiled in, so the hashes are computed once.
pub fn inline_script_hashes(html: &str) -> Vec<String> {
    use sha2::{Digest, Sha256};
    let mut out = Vec::new();
    let mut rest = html;
    while let Some(start) = rest.find("<script") {
        let tag_end = match rest[start..].find('>') {
            Some(e) => start + e + 1,
            None => break,
        };
        let tag = &rest[start..tag_end];
        let Some(close) = rest[tag_end..].find("</script>") else {
            break;
        };
        let body = &rest[tag_end..tag_end + close];
        if !tag.contains("src=") {
            let digest = Sha256::digest(body.as_bytes());
            out.push(format!(
                "'sha256-{}'",
                data_encoding::BASE64.encode(&digest)
            ));
        }
        rest = &rest[tag_end + close + "</script>".len()..];
    }
    out
}

fn script_sources(page: Page) -> &'static str {
    static CONSOLE: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    static DOCS: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    let (cell, html) = match page {
        Page::Console => (&CONSOLE, INDEX_HTML),
        Page::Docs => (&DOCS, DOCS_HTML),
    };
    cell.get_or_init(|| inline_script_hashes(html).join(" "))
}

/// The policy for the console and the API explorer: scripts only from this
/// server or the exact inline blocks shipped in the page (by hash), no
/// plugins, no base-URI or form hijacking, framing by this site only.
/// Inline styles stay allowed (the pages use style attributes). `host` adds
/// explicit ws:/wss: sources for the console websocket for browsers whose
/// `'self'` does not cover websockets.
pub fn content_security_policy(page: Page, host: Option<&str>) -> String {
    let ws = host
        .filter(|h| {
            !h.is_empty()
                && h.chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | ':' | '-' | '[' | ']'))
        })
        .map(|h| format!(" ws://{h} wss://{h}"))
        .unwrap_or_default();
    format!(
        "default-src 'self'; script-src 'self' {}; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'{ws}; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'self'",
        script_sources(page)
    )
}

/// Decompress a gzipped static asset once, on first request from a client
/// that does not accept gzip.
pub fn gunzipped(cell: &'static std::sync::OnceLock<Vec<u8>>, gz: &[u8]) -> &'static [u8] {
    cell.get_or_init(|| {
        use std::io::Read;
        let mut out = Vec::new();
        flate2::read::GzDecoder::new(gz)
            .read_to_end(&mut out)
            .expect("embedded asset is valid gzip");
        out
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// L3: every inline script is covered by a hash and no inline event
    /// handler attributes remain (they would need 'unsafe-inline').
    #[test]
    fn csp_covers_inline_scripts_and_pages_have_no_inline_handlers() {
        for (page, html) in [(Page::Console, INDEX_HTML), (Page::Docs, DOCS_HTML)] {
            let blocks = html.matches("<script>").count();
            assert!(blocks >= 1);
            assert_eq!(inline_script_hashes(html).len(), blocks);
            let csp = content_security_policy(page, Some("localhost:8053"));
            assert!(
                !csp.contains("'unsafe-inline'; img")
                    || csp.contains("style-src 'self' 'unsafe-inline'")
            );
            assert!(!csp.contains("script-src 'self' 'unsafe-inline'"));
            assert!(csp.contains("object-src 'none'") && csp.contains("base-uri 'none'"));
            assert!(csp.contains("wss://localhost:8053"));
            for (i, _) in html.match_indices(" on") {
                let rest = &html[i + 3..];
                let name: String = rest
                    .chars()
                    .take_while(|c| c.is_ascii_lowercase())
                    .collect();
                let is_attr = !name.is_empty() && rest[name.len()..].starts_with("=\"");
                assert!(!is_attr, "inline handler on{name}= at byte {i}");
            }
        }
        // A hostile Host header cannot inject policy directives.
        let csp = content_security_policy(Page::Console, Some("evil; script-src *"));
        assert!(!csp.contains("evil"));
    }

    #[test]
    fn swagger_assets_decompress() {
        static JS: std::sync::OnceLock<Vec<u8>> = std::sync::OnceLock::new();
        static CSS: std::sync::OnceLock<Vec<u8>> = std::sync::OnceLock::new();
        let js = gunzipped(&JS, SWAGGER_JS_GZ);
        assert!(js.len() > 1_000_000 && std::str::from_utf8(js).is_ok());
        assert!(gunzipped(&CSS, SWAGGER_CSS_GZ).starts_with(b".swagger-ui"));
    }
}
