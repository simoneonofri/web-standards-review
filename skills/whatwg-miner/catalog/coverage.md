# WHATWG security-mining coverage

Official standards assessed: 22. Curated controls: 43.

| Standard | Controls | State | Residual gap |
| --- | ---: | --- | --- |
| [Compatibility](https://compat.spec.whatwg.org/) | 0 | `assessed-no-reusable-control` | Compatibility surfaces are legacy/non-standard behavior; no explicit reusable security control was curated in the bounded pass. |
| [Compression](https://compression.spec.whatwg.org/) | 0 | `assessed-no-reusable-control` | Malformed streams fail, but decompression-bomb and resource-amplification limits are not explicitly defined as reusable security controls. |
| [Console](https://console.spec.whatwg.org/) | 0 | `assessed-no-reusable-control` | Console formatting and debugging behavior were assessed; privacy or diagnostic leakage concerns do not yield an explicit reusable access control. |
| [Cookie Store API](https://cookiestore.spec.whatwg.org/) | 4 | `cataloged` | RFC 6265bis supplies much of the normative cookie security model; follow that dependency for SameSite, Domain, Path, and prefix details. |
| [DOM](https://dom.spec.whatwg.org/) | 1 | `partial` | Trusted Types attribute integration is cataloged; DOM is cross-cutting and downstream HTML sinks and mutation consumers remain dependency-heavy. |
| [Encoding](https://encoding.spec.whatwg.org/) | 2 | `cataloged` | Decoder-specific malformed-sequence behavior remains distributed across individual encoding algorithms. |
| [Fetch](https://fetch.spec.whatwg.org/) | 6 | `partial` | CORS, filtering, headers, redirects, and CORP are covered initially; mixed content, CSP, SRI, PNA, ORB, cache partitioning, and authentication dependencies require separate standards review. |
| [File System](https://fs.spec.whatwg.org/) | 3 | `cataloged` | User-selected file permission lifetime and revocation are supplied by integrating specifications and user-agent policy. |
| [Fullscreen API](https://fullscreen.spec.whatwg.org/) | 3 | `cataloged` | Keyboard lock integration and platform UI details are not fully enumerated in this initial catalog. |
| [HTML](https://html.spec.whatwg.org/multipage/) | 7 | `partial` | HTML is very large; origin, sandbox, COOP/COEP, canvas, activation, and meta CSP are covered, while navigation, messaging, workers, storage, embeds, forms, and many feature-specific guards need targeted follow-up. |
| [Infra](https://infra.spec.whatwg.org/) | 0 | `assessed-no-reusable-control` | Infra defines generic data structures and algorithms; none were promoted without an explicit security-boundary consequence. |
| [MIME Sniffing](https://mimesniff.spec.whatwg.org/) | 2 | `cataloged` | Context-specific sniffing tables and Fetch's X-Content-Type-Options integration need joint review for a concrete API. |
| [Notifications API](https://notifications.spec.whatwg.org/) | 1 | `cataloged` | Permission is cataloged; frequency, deceptive content, and platform anti-abuse policy are largely user-agent concerns rather than explicit reusable controls here. |
| [Quirks Mode](https://quirks.spec.whatwg.org/) | 0 | `assessed-no-reusable-control` | Legacy CSS/selector compatibility behavior did not expose an explicit reusable security mechanism. |
| [Storage](https://storage.spec.whatwg.org/) | 2 | `cataloged` | Quota and clearing are implementation-defined; storage partitioning can evolve beyond the current origin tuple. |
| [Streams](https://streams.spec.whatwg.org/) | 0 | `assessed-no-reusable-control` | Backpressure, cancellation, and error propagation are generic resource-management primitives unless an integrating API establishes a security boundary. |
| [Test Utils](https://testutils.spec.whatwg.org/) | 0 | `assessed-no-reusable-control` | The standard is an internal testing surface and was classified testing-only, not a production API security-control source. |
| [URL](https://url.spec.whatwg.org/) | 2 | `cataloged` | Most validation errors are non-fatal; each integrating API must decide which URL conditions are security-fatal. |
| [URL Pattern](https://urlpattern.spec.whatwg.org/) | 1 | `cataloged` | Regexp-group restriction is informative integration guidance, not a built-in complexity bound or policy language. |
| [Web IDL](https://webidl.spec.whatwg.org/) | 4 | `partial` | Exposure and exception redaction are covered; type conversion and binding exceptions remain generic unless tied to a concrete API boundary. |
| [WebSockets](https://websockets.spec.whatwg.org/) | 2 | `cataloged` | Server-side Origin validation, authentication, TLS, extensions, and protocol message authorization require RFC and application review. |
| [XMLHttpRequest](https://xhr.spec.whatwg.org/) | 3 | `cataloged` | XHR delegates most network security semantics to Fetch; use the Fetch catalog for complete CORS and response-filtering behavior. |

## Counts by category

| Category | Count |
| --- | ---: |
| `authority-and-permission` | 4 |
| `content-and-type-safety` | 6 |
| `input-validation-and-failure` | 2 |
| `interface-exposure` | 4 |
| `network-and-request-policy` | 8 |
| `origin-and-isolation` | 10 |
| `resource-and-abuse-control` | 1 |
| `storage-and-state` | 5 |
| `user-intent-and-visibility` | 3 |

## Global limitations

- Living Standards change continuously; anchors and semantics require revalidation after refresh.
- The catalog records specification mechanisms, not browser implementation, interoperability, or deployment.
- Large cross-cutting standards are intentionally marked `partial` where bounded initial mining cannot establish exhaustiveness.
- Zero controls means no reusable control was curated under this taxonomy; it does not mean no security relevance.
