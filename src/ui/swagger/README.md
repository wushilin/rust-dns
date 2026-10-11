Vendored [swagger-ui-dist](https://www.npmjs.com/package/swagger-ui-dist) 5.33.0
(Apache-2.0, see LICENSE and NOTICE), embedded in the binary for the console's
API explorer at /rust-dns/docs so it works without internet access.

Source: https://registry.npmjs.org/swagger-ui-dist/-/swagger-ui-dist-5.33.0.tgz
Verified against the registry's sha512 integrity before vendoring.
To update: download the new tarball, verify `dist.integrity`, copy
`swagger-ui-bundle.js`, `swagger-ui.css`, `LICENSE`, `NOTICE`, bump VERSION,
then `gzip -9 -n` the two assets (they are stored and embedded gzipped; the
bundle is too large to commit uncompressed).

SHA-256 of the uncompressed 5.33.0 files:
62df541529080464a7660adc793eab7128c6193ce3be24ddc1e0e0a4a63edc2f  swagger-ui-bundle.js
1ac324f7dcd27e4b9386b4bd6421271ec147e922a22c05ba24b11515e9aa6321  swagger-ui.css
