pub const INDEX_HTML: &str = include_str!("index.html");

/// API explorer page (Swagger UI) served at /docs.
pub const DOCS_HTML: &str = include_str!("docs.html");
/// Vendored Swagger UI assets, stored gzipped (served as-is to clients that
/// accept gzip, which is every browser).
pub const SWAGGER_JS_GZ: &[u8] = include_bytes!("swagger/swagger-ui-bundle.js.gz");
pub const SWAGGER_CSS_GZ: &[u8] = include_bytes!("swagger/swagger-ui.css.gz");
pub const SWAGGER_VERSION: &str = include_str!("swagger/VERSION");

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

    #[test]
    fn swagger_assets_decompress() {
        static JS: std::sync::OnceLock<Vec<u8>> = std::sync::OnceLock::new();
        static CSS: std::sync::OnceLock<Vec<u8>> = std::sync::OnceLock::new();
        let js = gunzipped(&JS, SWAGGER_JS_GZ);
        assert!(js.len() > 1_000_000 && std::str::from_utf8(js).is_ok());
        assert!(gunzipped(&CSS, SWAGGER_CSS_GZ).starts_with(b".swagger-ui"));
    }
}
