# WebAppSec API security control catalog

This generated index is scoped by the exact [2026 Web Application Security Working Group charter](https://w3c.github.io/charter-drafts/2026/charter-wg-webappsec-2026.html). Charter inclusion establishes scope only; each mechanism links to specification evidence.

## Inventory

| Item | Count |
| --- | ---: |
| Normative charter deliverables | 17 |
| Tentative charter deliverables | 3 |
| Named other deliverables | 4 |
| Reusable security controls | 28 |
| Secure defaults | 15 |
| Exceptions and opt-outs | 20 |

## Control families

| Family | Controls |
| --- | ---: |
| clear-site-data | 1 |
| content-security-policy | 4 |
| credential-management | 1 |
| device-bound-session-credentials | 1 |
| document-policy | 1 |
| fetch-metadata | 1 |
| mixed-content | 1 |
| permissions | 3 |
| permissions-policy | 3 |
| referrer-policy | 1 |
| secure-contexts | 2 |
| subresource-integrity | 2 |
| trusted-types | 3 |
| upgrade-insecure-requests | 1 |
| web-cryptography | 1 |
| well-known-security-endpoints | 2 |

## Controls

| ID | Control | Strength | Defaults | Exceptions | Primary evidence |
| --- | --- | --- | --- | --- | --- |
| WAM-SC-01 | Expose sensitive APIs only in secure contexts | framework-defined | WAD-01 | WAE-01, WAE-02, WAE-03, WAE-15 | [2.1 Integration with WebIDL](https://www.w3.org/TR/2023/CRD-secure-contexts-20231110/#integration-idl) |
| WAM-SC-02 | Use the shared potentially-trustworthy decision | algorithm-required | WAD-02 | WAE-01, WAE-02, WAE-03 | [3.1 Is origin potentially trustworthy?](https://www.w3.org/TR/2023/CRD-secure-contexts-20231110/#is-origin-trustworthy) |
| WAM-PERM-01 | Specify and register a powerful feature | MUST | WAD-03 | WAE-04 | [4 Specifying a powerful feature](https://www.w3.org/TR/2025/WD-permissions-20251006/#specifying-a-powerful-feature) |
| WAM-PERM-02 | Deny permission in insecure or policy-disabled contexts | algorithm-required | WAD-04 | — | [5.1 Reading the current permission state](https://www.w3.org/TR/2025/WD-permissions-20251006/#reading-current-states) |
| WAM-PERM-03 | Define permission lifetime and revocation behavior | SHOULD | WAD-03 | WAE-04 | [4 Specifying a powerful feature: permission lifetime](https://www.w3.org/TR/2025/WD-permissions-20251006/#specifying-a-powerful-feature) |
| WAM-PP-01 | Define a policy-controlled feature and default allowlist | framework-defined | WAD-05 | WAE-05, WAE-06 | [4.1 Policy-controlled Features](https://www.w3.org/TR/2026/WD-permissions-policy-1-20260618/#features) |
| WAM-PP-02 | Bound delegation through inherited and container policy | algorithm-required | WAD-05 | WAE-06 | [4.3 Inherited policies](https://www.w3.org/TR/2026/WD-permissions-policy-1-20260618/#inherited-policies) |
| WAM-PP-03 | Provide enforced and report-only policy delivery | framework-defined | — | WAE-06, WAE-10 | [6 Delivery](https://www.w3.org/TR/2026/WD-permissions-policy-1-20260618/#delivery) |
| WAM-CSP-01 | Constrain resource, connection, and execution destinations | framework-defined | WAD-06 | WAE-07, WAE-08 | [3.1 Content-Security-Policy](https://www.w3.org/TR/2026/WD-CSP3-20260505/#csp-header) |
| WAM-CSP-02 | Gate inline and dynamically trusted code | algorithm-required | WAD-06 | WAE-07, WAE-08 | [6.1.10.3 script-src Inline Check](https://www.w3.org/TR/2026/WD-CSP3-20260505/#script-src-inline) |
| WAM-CSP-03 | Control embedding and document capabilities | framework-defined | — | WAE-06 | [6.4.2 frame-ancestors](https://www.w3.org/TR/2026/WD-CSP3-20260505/#directive-frame-ancestors) |
| WAM-CSP-04 | Separate CSP observation from enforcement | framework-defined | — | WAE-10 | [3.2 Content-Security-Policy-Report-Only](https://www.w3.org/TR/2026/WD-CSP3-20260505/#cspro-header) |
| WAM-TT-01 | Type injection sinks | framework-defined | WAD-07 | WAE-09 | [2.1 Injection sinks](https://www.w3.org/TR/2026/WD-trusted-types-20260623/#injection-sinks) |
| WAM-TT-02 | Require Trusted Types and restrict policy creation | framework-defined | WAD-07 | WAE-09, WAE-10 | [4.2.1 require-trusted-types-for](https://www.w3.org/TR/2026/WD-trusted-types-20260623/#require-trusted-types-for-csp-directive) |
| WAM-TT-03 | Treat the default Trusted Types policy as a bounded compatibility path | synthesis | WAD-07 | WAE-09 | [2.3.4 Default policy](https://www.w3.org/TR/2026/WD-trusted-types-20260623/#default-policy-hdr) |
| WAM-MIX-01 | Upgrade or block mixed content before use | algorithm-required | WAD-08 | WAE-11 | [4.1 Upgrade a mixed content request](https://www.w3.org/TR/2023/CRD-mixed-content-20230223/#upgrade-algorithm) |
| WAM-UIR-01 | Offer declarative insecure-request upgrade and inheritance | framework-defined | WAD-09 | WAE-11 | [3 Upgrading Insecure Resource Requests](https://www.w3.org/TR/2015/CR-upgrade-insecure-requests-20151008/#upgrading) |
| WAM-SRI-01 | Verify subresource bytes against strongest integrity metadata | algorithm-required | WAD-10 | WAE-12 | [3.3.3 Get the strongest metadata from set](https://www.w3.org/TR/2026/WD-sri-2-20260320/#get-the-strongest-metadata) |
| WAM-SRI-02 | Block missing or mismatching integrity under Integrity Policy | algorithm-required | WAD-10 | WAE-10, WAE-12 | [3.7 Handling integrity violations](https://www.w3.org/TR/2026/WD-sri-2-20260320/#handling-integrity-violations) |
| WAM-FETCH-01 | Expose trustworthy request context for server-side isolation | framework-defined | — | WAE-13 | [2 Fetch Metadata Headers](https://www.w3.org/TR/2025/WD-fetch-metadata-20250401/#framework) |
| WAM-REF-01 | Minimize referrer disclosure | algorithm-required | — | WAE-14 | [8 Algorithms](https://www.w3.org/TR/2017/CR-referrer-policy-20170126/#algorithms) |
| WAM-CLEAR-01 | Define origin-bound data clearing and execution-context invalidation | framework-defined | — | WAE-16 | [3.1 Clear-Site-Data](https://www.w3.org/TR/2017/WD-clear-site-data-20171130/#header) |
| WAM-CRED-01 | Bind credential operations to origin, ancestors, and mediation | algorithm-required | WAD-11 | WAE-17 | [2.1.1.1 Same-Origin with its Ancestors](https://www.w3.org/TR/2026/WD-credential-management-1-20260702/#algorithm-same-origin-with-ancestors) |
| WAM-DBSC-01 | Bind session refresh to a scoped device key proof | algorithm-required | WAD-12 | WAE-18 | [7.4 Session scope](https://www.w3.org/TR/2025/WD-dbsc-1-20250821/#framework-scope) |
| WAM-CRYPTO-01 | Constrain cryptographic capability by context, extractability, and usage | framework-defined | WAD-13 | WAE-15 | [10 Crypto interface](https://www.w3.org/TR/2025/WD-webcrypto-2-20250422/#x10-crypto-interface) |
| WAM-DOC-01 | Require and enforce document configuration preconditions | framework-defined | WAD-14 | WAE-10 | [7.2.3 Require-Document-Policy](https://wicg.github.io/document-policy/#require-document-policy-http-header) |
| WAM-WELL-01 | Discover password-change UI only from a trustworthy origin | algorithm-required | WAD-02 | WAE-19 | [3 Change Password URLs](https://www.w3.org/TR/2024/WD-change-password-url-20240603/#semantics) |
| WAM-WELL-02 | Bind passkey endpoint discovery to HTTPS and RP ID | MUST | WAD-15 | WAE-20 | [3 Passkey Endpoints URLs](https://www.w3.org/TR/2026/WD-passkey-endpoints-1-20260114/#semantics) |

## Secure defaults

| ID | Default | Explicitness | Strength | Controls | Primary evidence |
| --- | --- | --- | --- | --- | --- |
| WAD-01 | Sensitive interface absent in non-secure contexts | explicit-platform-default | framework-defined | WAM-SC-01 | [[SecureContext]](https://webidl.spec.whatwg.org/#SecureContext) |
| WAD-02 | Untrustworthy origins fail trust-gated operations | explicit-algorithmic-default | algorithm-required | WAM-SC-02, WAM-WELL-01 | [3.1 Is origin potentially trustworthy?](https://www.w3.org/TR/2023/CRD-secure-contexts-20231110/#is-origin-trustworthy) |
| WAD-03 | Unspecified powerful-feature permission starts at prompt | explicit-platform-default | framework-defined | WAM-PERM-01, WAM-PERM-03 | [4 Specifying a powerful feature: Default permission state](https://www.w3.org/TR/2025/WD-permissions-20251006/#specifying-a-powerful-feature) |
| WAD-04 | Insecure or policy-disabled permission state is denied | explicit-algorithmic-default | algorithm-required | WAM-PERM-02 | [5.1 Reading the current permission state](https://www.w3.org/TR/2025/WD-permissions-20251006/#reading-current-states) |
| WAD-05 | Choose same-origin-only delegation for sensitive features | recommended-synthesis | synthesis | WAM-PP-01, WAM-PP-02 | [4.8 Default Allowlists](https://www.w3.org/TR/2026/WD-permissions-policy-1-20260618/#default-allowlists) |
| WAD-06 | CSP-protected inline execution is blocked without authorization | explicit-algorithmic-default | algorithm-required | WAM-CSP-01, WAM-CSP-02 | [6.1.10.3 script-src Inline Check](https://www.w3.org/TR/2026/WD-CSP3-20260505/#script-src-inline) |
| WAD-07 | Enforced Trusted Types reject sink type mismatch | explicit-algorithmic-default | algorithm-required | WAM-TT-01, WAM-TT-02, WAM-TT-03 | [4.2.4 Should sink type mismatch be blocked?](https://www.w3.org/TR/2026/WD-trusted-types-20260623/#should-block-sink-type-mismatch) |
| WAD-08 | Mixed content is upgraded when eligible and otherwise blocked | explicit-algorithmic-default | algorithm-required | WAM-MIX-01 | [4 Algorithms](https://www.w3.org/TR/2023/CRD-mixed-content-20230223/#algorithms) |
| WAD-09 | Declared insecure requests are rewritten before dispatch | explicit-algorithmic-default | algorithm-required | WAM-UIR-01 | [4.1 Upgrade request](https://www.w3.org/TR/2015/CR-upgrade-insecure-requests-20151008/#upgrade-request) |
| WAD-10 | Integrity mismatch blocks protected resource use | explicit-algorithmic-default | algorithm-required | WAM-SRI-01, WAM-SRI-02 | [3.7 Handling integrity violations](https://www.w3.org/TR/2026/WD-sri-2-20260320/#handling-integrity-violations) |
| WAD-11 | Credential retrieval is not ambient across ancestor origins | explicit-algorithmic-default | algorithm-required | WAM-CRED-01 | [2.5.1 Request a Credential](https://www.w3.org/TR/2026/WD-credential-management-1-20260702/#algorithm-request) |
| WAD-12 | Only in-scope eligible requests trigger DBSC refresh | explicit-algorithmic-default | algorithm-required | WAM-DBSC-01 | [8.3 Identify if a request is allowed to refresh](https://www.w3.org/TR/2025/WD-dbsc-1-20250821/#algo-request-allows-refresh) |
| WAD-13 | Use non-extractable, minimally scoped keys where export is unnecessary | recommended-synthesis | synthesis | WAM-CRYPTO-01 | [13.4 CryptoKey interface members](https://www.w3.org/TR/2025/WD-webcrypto-2-20250422/#x13-4-cryptokey-interface-members) |
| WAD-14 | Block a document incompatible with required policy | explicit-algorithmic-default | algorithm-required | WAM-DOC-01 | [9.7 Should response be blocked due to document policy?](https://wicg.github.io/document-policy/#algo-should-reponse-to-request-be-blocked) |
| WAD-15 | Passkey endpoint discovery is HTTPS, same-RP, and non-redirecting | explicit-algorithmic-default | MUST | WAM-WELL-02 | [3 Passkey Endpoints URLs](https://www.w3.org/TR/2026/WD-passkey-endpoints-1-20260114/#semantics) |

## Exceptions and opt-outs

| ID | Exception | Strength | Controls | Primary evidence |
| --- | --- | --- | --- | --- |
| WAE-01 | Loopback and local origins may be potentially trustworthy | algorithm-required | WAM-SC-01, WAM-SC-02 | [3.1 Is origin potentially trustworthy?](https://www.w3.org/TR/2023/CRD-secure-contexts-20231110/#is-origin-trustworthy) |
| WAE-02 | User agents may designate development origins trustworthy | MAY | WAM-SC-01, WAM-SC-02 | [7.2 Development Environments](https://www.w3.org/TR/2023/CRD-secure-contexts-20231110/#development-environments) |
| WAE-03 | Authenticated packaged-application schemes may be trusted | MAY | WAM-SC-01, WAM-SC-02 | [7.1 Packaged Applications](https://www.w3.org/TR/2023/CRD-secure-contexts-20231110/#packaged-applications) |
| WAE-04 | A powerful feature may override Permissions defaults | MAY | WAM-PERM-01, WAM-PERM-03 | [4 Specifying a powerful feature](https://www.w3.org/TR/2025/WD-permissions-20251006/#specifying-a-powerful-feature) |
| WAE-05 | Permissions Policy can default a feature to every origin | framework-defined | WAM-PP-01 | [4.8 Default Allowlists](https://www.w3.org/TR/2026/WD-permissions-policy-1-20260618/#default-allowlists) |
| WAE-06 | Parent policy can explicitly delegate a feature | framework-defined | WAM-PP-01, WAM-PP-02, WAM-PP-03, WAM-CSP-03 | [6.2 iframe allow attribute](https://www.w3.org/TR/2026/WD-permissions-policy-1-20260618/#iframe-allow-attribute) |
| WAE-07 | CSP unsafe sources explicitly re-enable risky behavior | framework-defined | WAM-CSP-01, WAM-CSP-02 | [2.3.1 Source Lists](https://www.w3.org/TR/2026/WD-CSP3-20260505/#framework-directive-source-list) |
| WAE-08 | strict-dynamic delegates trust from a nonce or hash | framework-defined | WAM-CSP-01, WAM-CSP-02 | [8.2 Usage of strict-dynamic](https://www.w3.org/TR/2026/WD-CSP3-20260505/#strict-dynamic-usage) |
| WAE-09 | Trusted Types default policy can convert legacy strings | framework-defined | WAM-TT-01, WAM-TT-02, WAM-TT-03 | [3.5 Process value with a default policy](https://www.w3.org/TR/2026/WD-trusted-types-20260623/#process-value-with-a-default-policy-algorithm) |
| WAE-10 | Report-only policy observes without blocking | framework-defined | WAM-PP-03, WAM-CSP-04, WAM-TT-02, WAM-SRI-02, WAM-DOC-01 | [3.2 Content-Security-Policy-Report-Only](https://www.w3.org/TR/2026/WD-CSP3-20260505/#cspro-header) |
| WAE-11 | Upgrade behavior is conditional and has no insecure fallback guarantee | algorithm-required | WAM-MIX-01, WAM-UIR-01 | [3 Content Categories](https://www.w3.org/TR/2023/CRD-mixed-content-20230223/#categories) |
| WAE-12 | Cross-origin SRI requires an eligible response | algorithm-required | WAM-SRI-01, WAM-SRI-02 | [5.3 Cross-origin data leakage](https://www.w3.org/TR/2026/WD-sri-2-20260320/#cross-origin-data-leakage) |
| WAE-13 | Fetch Metadata may be absent or require compatibility handling | informative-recommendation | WAM-FETCH-01 | [5 Deployment Considerations](https://www.w3.org/TR/2025/WD-fetch-metadata-20250401/#deployment-considerations) |
| WAE-14 | Authors can select a more permissive referrer policy | framework-defined | WAM-REF-01 | [3 Referrer Policies](https://www.w3.org/TR/2017/CR-referrer-policy-20170126/#referrer-policies) |
| WAE-15 | WebCrypto keeps getRandomValues outside the secure-context gate | framework-defined | WAM-SC-01, WAM-CRYPTO-01 | [10 Crypto interface](https://www.w3.org/TR/2025/WD-webcrypto-2-20250422/#x10-crypto-interface) |
| WAE-16 | Clear-Site-Data wildcard is intentionally forward-compatible | informative-recommendation | WAM-CLEAR-01 | [3.1 Clear-Site-Data wildcard](https://www.w3.org/TR/2017/WD-clear-site-data-20171130/#header) |
| WAE-17 | Credential mediation can be silent when explicitly permitted | framework-defined | WAM-CRED-01 | [2.3.2 Mediation Requirements](https://www.w3.org/TR/2026/WD-credential-management-1-20260702/#mediation-requirements) |
| WAE-18 | Cross-origin DBSC single sign-on is a separate tentative deliverable | informative-recommendation | WAM-DBSC-01 | [Tentative deliverable: DBSC for Single Sign-On](https://w3c.github.io/charter-drafts/2026/charter-wg-webappsec-2026.html#dbsc-sso) |
| WAE-19 | Change-password discovery uses constrained temporary redirects | SHOULD | WAM-WELL-01 | [3 Change Password URLs](https://www.w3.org/TR/2024/WD-change-password-url-20240603/#semantics) |
| WAE-20 | Passkey endpoint discovery may return an empty object but never redirect | MAY | WAM-WELL-02 | [3.1 Server Response](https://www.w3.org/TR/2026/WD-passkey-endpoints-1-20260114/#response) |

## Charter deliverables

| Category | Deliverable | Draft state | Mining status |
| --- | --- | --- | --- |
| normative | [Fetch Metadata Request Headers](https://www.w3.org/TR/fetch-metadata/) | Working Draft | control-mined |
| normative | [A Well-Known URL for Changing Passwords](https://www.w3.org/TR/change-password-url/) | Working Draft | control-mined |
| normative | [A Well-Known URL for Relying Party Passkey Endpoints](https://www.w3.org/TR/passkey-endpoints-1/) | Working Draft | control-mined |
| normative | [Trusted Types](https://www.w3.org/TR/trusted-types/) | Working Draft | control-mined |
| normative | [Content Security Policy Level 3](https://www.w3.org/TR/CSP3/) | Working Draft | control-mined |
| normative | [Mixed Content](https://www.w3.org/TR/mixed-content/) | Candidate Recommendation Draft | control-mined |
| normative | [Upgrade Insecure Requests](https://www.w3.org/TR/upgrade-insecure-requests/) | Candidate Recommendation | control-mined |
| normative | [Secure Contexts](https://www.w3.org/TR/secure-contexts/) | Candidate Recommendation Draft | control-mined |
| normative | [Clear Site Data](https://www.w3.org/TR/clear-site-data/) | Working Draft | control-mined |
| normative | [Referrer Policy](https://www.w3.org/TR/referrer-policy/) | Candidate Recommendation | control-mined |
| normative | [Credential Management Level 1](https://www.w3.org/TR/credential-management-1/) | Working Draft | control-mined |
| normative | [Permissions](https://www.w3.org/TR/permissions/) | Working Draft | control-mined |
| normative | [Permissions Policy](https://www.w3.org/TR/permissions-policy-1/) | Working Draft | control-mined |
| normative | [Document Policy](https://wicg.github.io/document-policy/) | Incubation in the Web Platform Incubator Community Group | editor-draft-control-mined |
| normative | [Subresource Integrity Level 2](https://www.w3.org/TR/sri-2/) | Working Draft | control-mined |
| normative | [Device Bound Session Credentials](https://www.w3.org/TR/dbsc-1/) | Working Draft | control-mined |
| normative | [Web Cryptography Level 2](https://www.w3.org/TR/webcrypto-2/) | Working Draft | control-mined |
| tentative | [Source Code Transparency](https://github.com/w3c/webappsec/blob/main/meetings/2023/2023-09-15-TPAC-minutes.md#source-code-transparency-sketch) | Early proposal discussed by the Working Group | inventory-only |
| tentative | [Securer Contexts](https://github.com/mikewest/securer-contexts) | Incubation proposal | inventory-only |
| tentative | [Device Bound Session Credentials for Single Sign-On](https://github.com/WICG/dbsc-sso) | Incubation in the Web Platform Incubator Community Group | inventory-only |
| other | [Post-Spectre Web Development](https://www.w3.org/TR/post-spectre-webdev/) | Working Draft | inventory-only |
| other | [Content Security Policy: Embedded Enforcement](https://www.w3.org/TR/csp-embedded-enforcement/) | Working Draft | inventory-only |
| other | Security and privacy model for cookies | Not stated | inventory-only |
| other | Permissions best practices | Not stated | inventory-only |

## Limits

This is a targeted initial mechanism catalog, not exhaustive clause-level mining, an implementation-support statement, or proof that an API is secure. Apply controls by applicability, preserve evidence class and status, and review linked exceptions before making a finding.
