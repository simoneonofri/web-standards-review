# WHATWG reusable security controls

Curated controls: 43 across 15 standards. Evidence snapshot date: 2026-08-04.

> This is a review aid, not an exhaustive conformance statement. Follow every official anchor before relying on a finding.

## Cookie Store API

### [HttpOnly script-visibility filter](https://cookiestore.spec.whatwg.org/#cookie-concept)

- Category: `storage-and-state`
- Status: `normative`; evidence: `security_control`; confidence: `high`
- Evidence (semantic_summary): Semantic summary: Cookie Store exposes only script-visible cookies; a cookie whose http-only flag is set is excluded by the retrieval model.
- Applies when: Script access through Cookie Store in Window or ServiceWorker contexts.
- Secure default: HttpOnly cookies are not script-visible.
- Failure or exception: Filtered cookies are absent rather than disclosed with an error.
- Explicit exceptions: Visibility also depends on the RFC 6265bis retrieval model and cookie scope.
- Dependencies: RFC 6265bis retrieval model
- Limitation: Does not protect non-HttpOnly cookies or prove implementation behavior.

### [Reserved secure cookie-prefix guards](https://cookiestore.spec.whatwg.org/#set-cookie-algorithm)

- Category: `storage-and-state`
- Status: `normative`; evidence: `security_control`; confidence: `high`
- Evidence (semantic_summary): Semantic summary: the write algorithm rejects incompatible uses of __Host-, __Secure-, __Http-, and __Host-Http- prefixes, including invalid host path conditions.
- Applies when: Cookie Store writes whose names use a reserved security prefix.
- Secure default: Prefix semantics are enforced before storage.
- Failure or exception: Return failure.
- Explicit exceptions: Legacy cookie APIs can have different enforcement; the prefix section documents graceful degradation.
- Dependencies: RFC 6265bis cookie prefixes
- Limitation: Prefix guarantees are conditional on the exact prefix and attributes.

### [Secure-context interface exposure](https://cookiestore.spec.whatwg.org/#cookiestore)

- Category: `interface-exposure`
- Status: `normative`; evidence: `security_control`; confidence: `high`
- Evidence (semantic_summary): Semantic summary: Cookie Store interfaces are annotated with Web IDL SecureContext exposure guards.
- Applies when: JavaScript exposure of Cookie Store interfaces.
- Secure default: The guarded interface is absent outside a secure context.
- Failure or exception: Web IDL does not expose the construct; calls cannot be made through that interface.
- Explicit exceptions: Exposure sets differ between Window, ServiceWorker, and registration interfaces.
- Dependencies: Web IDL [SecureContext], Secure Contexts
- Limitation: Secure context is necessary but not sufficient for safe cookie use.

### [Secure-only cookie writes](https://cookiestore.spec.whatwg.org/#secure-cookies)

- Category: `storage-and-state`
- Status: `mixed`; evidence: `security_control`; confidence: `high`
- Evidence (semantic_summary): Semantic summary: the API permits writes only as Secure cookies and upgrades a modified non-Secure cookie to Secure.
- Applies when: Cookie creation and modification through Cookie Store.
- Secure default: Writes use Secure semantics; reads retain migration compatibility.
- Failure or exception: A write that cannot satisfy secure-cookie rules fails through the set-cookie algorithm.
- Explicit exceptions: Non-Secure cookies remain readable to support migration.
- Dependencies: Secure Contexts, RFC 6265bis
- Limitation: The cited security section summarizes behavior whose exact failure steps are defined elsewhere in the standard.

## DOM

### [Trusted Types validation for attribute mutation](https://dom.spec.whatwg.org/#interface-element)

- Category: `content-and-type-safety`
- Status: `normative`; evidence: `security_control`; confidence: `high`
- Evidence (semantic_summary): Semantic summary: Element attribute mutation algorithms obtain a Trusted Types-compliant value before changing the attribute.
- Applies when: Attribute sinks covered by Trusted Types integration during DOM mutation.
- Secure default: The verified value, not the unverified input, is used by the mutation algorithm.
- Failure or exception: Trusted Types enforcement can reject before the attribute changes.
- Explicit exceptions: Only attributes classified as Trusted Types sinks receive sink-specific enforcement.
- Dependencies: Trusted Types
- Limitation: Does not make arbitrary DOM mutation injection-safe and requires the dependency's sink classification and policy.

## Encoding

### [Illegal multibyte sequence ASCII-unmasking rule](https://encoding.spec.whatwg.org/#security-background)

- Category: `content-and-type-safety`
- Status: `mixed`; evidence: `security_rationale`; confidence: `high`
- Evidence (semantic_summary): Semantic summary: decoders must not let an illegal multibyte sequence mask an ASCII code point that can act as a syntax delimiter.
- Applies when: Decoding legacy multibyte encodings around illegal byte sequences.
- Secure default: Malformed input preserves security-relevant ASCII bytes rather than consuming them into one replacement character.
- Failure or exception: The illegal sequence produces replacement output while the ASCII byte is decoded separately.
- Explicit exceptions: The section documents a limited gb18030 end-of-queue exception.
- Dependencies: none recorded
- Limitation: The anchor explains the requirement; exact behavior is distributed across decoder algorithms.

### [Replacement encoding for unsafe labels](https://encoding.spec.whatwg.org/#replacement)

- Category: `content-and-type-safety`
- Status: `normative`; evidence: `security_control`; confidence: `high`
- Evidence (semantic_summary): Semantic summary: labels mapped to the replacement encoding are prevented from invoking legacy decoding behavior used in encoding-mismatch attacks.
- Applies when: Legacy encoding labels assigned to the replacement encoding by the standard's label table.
- Secure default: The label maps to a decoder that emits an error replacement instead of interpreting attacker-controlled bytes as the legacy encoding.
- Failure or exception: Decoding yields an error/replacement outcome rather than the unsafe legacy mapping.
- Explicit exceptions: Only labels explicitly mapped to replacement receive this behavior.
- Dependencies: none recorded
- Limitation: Consumers still need consistent encoding selection and UTF-8 where required.

## Fetch

### [Cross-Origin-Resource-Policy response gate](https://fetch.spec.whatwg.org/#cross-origin-resource-policy-header)

- Category: `origin-and-isolation`
- Status: `normative`; evidence: `security_control`; confidence: `high`
- Evidence (semantic_summary): Semantic summary: a resource can restrict no-CORS cross-origin embedding to same-origin or same-site requesters, with blocking integrated into Fetch.
- Applies when: No-CORS resource loads subject to CORP and embedder-policy checks.
- Secure default: No restriction is imposed unless the response supplies a recognized policy; once supplied, nonmatching requests are blocked.
- Failure or exception: Return blocked, which the caller's Fetch path handles as a network failure.
- Explicit exceptions: Navigation and embedder-policy conditions alter the internal check.
- Dependencies: HTML origin model, HTML COEP
- Limitation: `same-site` is weaker than `same-origin` and CORP does not authorize CORS reads.

### [Credential-aware CORS wildcard restriction](https://fetch.spec.whatwg.org/#cors-check)

- Category: `network-and-request-policy`
- Status: `normative`; evidence: `security_control`; confidence: `high`
- Evidence (semantic_summary): Semantic summary: wildcard origin authorization succeeds only for non-credentialed requests; credentialed sharing requires an explicit origin and credential opt-in.
- Applies when: CORS checks where request credentials mode may be include.
- Secure default: Credentialed responses are not exposed through wildcard authorization.
- Failure or exception: Return failure, surfaced by Fetch as a network error.
- Explicit exceptions: The wildcard is valid when credentials mode is not include.
- Dependencies: Fetch credentials mode, CORS response headers
- Limitation: An explicitly reflected attacker origin can still be unsafe if server policy is incorrect.

### [CORS cross-origin read authorization](https://fetch.spec.whatwg.org/#http-cors-protocol)

- Category: `network-and-request-policy`
- Status: `normative`; evidence: `security_control`; confidence: `high`
- Evidence (semantic_summary): Semantic summary: servers explicitly authorize origins, methods, headers, and credentialed sharing before a cross-origin response becomes readable to script.
- Applies when: Cross-origin Fetch-integrated requests using CORS mode.
- Secure default: Absent a valid server opt-in, cross-origin response sharing fails.
- Failure or exception: The CORS check or preflight produces a network error to the caller.
- Explicit exceptions: CORS-safelisted requests can avoid preflight but still require response authorization; no-CORS requests use opaque filtering instead.
- Dependencies: HTML origin model, HTTP
- Limitation: CORS is not authentication, CSRF protection, or a server-side network-boundary defense.

### [Cross-origin redirect credential stripping and rejection](https://fetch.spec.whatwg.org/#http-redirect-fetch)

- Category: `network-and-request-policy`
- Status: `normative`; evidence: `security_control`; confidence: `high`
- Evidence (semantic_summary): Semantic summary: Fetch rejects credential-bearing redirect URLs in CORS-tainted or cross-origin redirect paths and removes sensitive headers when origins change.
- Applies when: HTTP redirects during Fetch, especially CORS and origin-changing redirects.
- Secure default: Credentials embedded in a cross-origin redirect target do not propagate through the request.
- Failure or exception: Return a network error for prohibited credential-bearing locations.
- Explicit exceptions: Same-origin and request-mode conditions determine the exact redirect path.
- Dependencies: URL credentials, CORS, HTTP redirects
- Limitation: Does not prevent all redirect-based traffic analysis or server-side redirect abuse.

### [Filtered response boundary](https://fetch.spec.whatwg.org/#concept-filtered-response)

- Category: `origin-and-isolation`
- Status: `normative`; evidence: `security_control`; confidence: `high`
- Evidence (semantic_summary): Semantic summary: basic, CORS, opaque, and opaque-redirect filtered responses expose only the response data allowed for the request mode and origin relationship.
- Applies when: Responses returned through Fetch-integrated web APIs.
- Secure default: Opaque cross-origin responses hide status, headers, and body from script.
- Failure or exception: Disallowed data is filtered; some failed checks become network errors.
- Explicit exceptions: Internal and unsafe responses remain available only to specification algorithms, not normal script.
- Dependencies: HTML origin model, CORS
- Limitation: Filtering does not prevent the network request or all side channels.

### [Forbidden request-header guard](https://fetch.spec.whatwg.org/#forbidden-request-header)

- Category: `network-and-request-policy`
- Status: `normative`; evidence: `security_control`; confidence: `high`
- Evidence (semantic_summary): Semantic summary: Fetch classifies security-sensitive request headers as forbidden so script-facing header mutation cannot control them.
- Applies when: Web-exposed request construction and header mutation.
- Secure default: Forbidden headers remain under user-agent control.
- Failure or exception: Header mutation algorithms ignore or reject the forbidden pair according to their API.
- Explicit exceptions: The precise list includes conditional names and is maintained by Fetch.
- Dependencies: Web IDL API bindings
- Limitation: This is not a general HTTP header allowlist.

## File System

### [Same-origin handle deserialization guard](https://fs.spec.whatwg.org/#api-filesystemhandle)

- Category: `origin-and-isolation`
- Status: `normative`; evidence: `security_control`; confidence: `high`
- Evidence (semantic_summary): Semantic summary: deserializing a FileSystemHandle across a non-same-origin boundary is prohibited.
- Applies when: Structured serialization and transfer of FileSystemHandle values.
- Secure default: A handle remains bound to the serializing origin.
- Failure or exception: Throw DataCloneError.
- Explicit exceptions: Same-origin deserialization is permitted; subsequent entry access checks still apply.
- Dependencies: HTML same-origin, HTML structured serialization
- Limitation: Does not describe authority revocation after a valid same-origin transfer.

### [Default-denied file-system entry access](https://fs.spec.whatwg.org/#concepts)

- Category: `authority-and-permission`
- Status: `normative`; evidence: `security_control`; confidence: `high`
- Evidence (semantic_summary): Semantic summary: unless another specification supplies access algorithms, both query and request access return permission state denied.
- Applies when: File system entries whose access algorithms are not explicitly overridden.
- Secure default: Read and readwrite access are denied.
- Failure or exception: Return a denied access result; callers reject as appropriate rather than the access algorithm throwing.
- Explicit exceptions: Bucket file-system root access overrides this default and returns granted.
- Dependencies: Permissions, Storage
- Limitation: User-selected file and directory permission lifetimes are defined by integrating specifications and user agents.

### [Origin-partitioned bucket file system](https://fs.spec.whatwg.org/#sandboxed-filesystem)

- Category: `storage-and-state`
- Status: `normative`; evidence: `security_control`; confidence: `high`
- Evidence (semantic_summary): Semantic summary: the bucket file system is a Storage endpoint reached through the current storage bucket and grants access only within that origin-partitioned bucket.
- Applies when: `navigator.storage.getDirectory()` and bucket-file-system operations.
- Secure default: The root is scoped by the environment's storage key and bucket rather than an arbitrary host path.
- Failure or exception: Storage-key or environment failures prevent obtaining the bucket root through dependency algorithms.
- Explicit exceptions: Within the correctly selected bucket, entry access algorithms return granted without an additional prompt.
- Dependencies: Storage keys, Web IDL [SecureContext]
- Limitation: Quota, persistence, clearing, and partition-key details come from Storage and user-agent policy.

## Fullscreen API

### [Fullscreen awareness and reliable exit](https://fullscreen.spec.whatwg.org/#security-and-privacy-considerations)

- Category: `user-intent-and-visibility`
- Status: `informative`; evidence: `security_rationale`; confidence: `medium`
- Evidence (semantic_summary): Semantic summary: user agents should make fullscreen status apparent and provide an exit mechanism that always works to mitigate UI spoofing.
- Applies when: User-agent presentation and controls while content is fullscreen.
- Secure default: A persistent user override and awareness affordance are expected.
- Failure or exception: Not algorithmically specified; the user must remain able to exit.
- Explicit exceptions: Exact overlay, messaging, and preference UX is user-agent-defined.
- Dependencies: none recorded
- Limitation: Informative guidance does not define a testable API conformance result.

### [Fullscreen Permissions Policy](https://fullscreen.spec.whatwg.org/#permissions-policy-integration)

- Category: `authority-and-permission`
- Status: `normative`; evidence: `security_control`; confidence: `high`
- Evidence (semantic_summary): Semantic summary: fullscreen is a policy-controlled feature whose default allowlist is self; nested content requires explicit delegation.
- Applies when: Documents and nested browsing contexts requesting fullscreen.
- Secure default: Same-origin documents are allowed by default; cross-origin child content is not delegated by default.
- Failure or exception: The ready check fails and requestFullscreen rejects.
- Explicit exceptions: An iframe allow/allowfullscreen attribute or Permissions-Policy header can delegate the feature.
- Dependencies: Permissions Policy, HTML iframe policy
- Limitation: The default is not deny-all and embedding policy must be evaluated across the ancestor chain.

### [Transient-activation fullscreen gate](https://fullscreen.spec.whatwg.org/#dom-element-requestfullscreen)

- Category: `user-intent-and-visibility`
- Status: `normative`; evidence: `security_control`; confidence: `high`
- Evidence (semantic_summary): Semantic summary: requesting fullscreen requires a ready element, policy permission, support, and transient user activation, which is consumed on success.
- Applies when: Script calls to Element.requestFullscreen().
- Secure default: A page cannot enter fullscreen without current transient activation and policy authorization.
- Failure or exception: Reject the promise with TypeError and dispatch fullscreenerror through the algorithm.
- Explicit exceptions: A user-generated orientation change can satisfy the activation condition.
- Dependencies: HTML transient activation, Permissions Policy, DOM
- Limitation: User activation is a freshness signal, not proof that the user understood the transition.

## HTML

### [Canvas origin-clean tainting](https://html.spec.whatwg.org/#security-with-canvas-elements)

- Category: `origin-and-isolation`
- Status: `mixed`; evidence: `security_control`; confidence: `high`
- Evidence (semantic_summary): Semantic summary: cross-origin image use clears a bitmap's origin-clean flag; pixel-reading and serialization methods then refuse disclosure.
- Applies when: Canvas, OffscreenCanvas, and ImageBitmap data derived from cross-origin resources.
- Secure default: New bitmaps start origin-clean and become tainted when unsafe cross-origin content is incorporated.
- Failure or exception: Reading or serializing tainted data throws SecurityError.
- Explicit exceptions: CORS-authorized resources and algorithm-specific origin-clean propagation can preserve readability.
- Dependencies: Fetch CORS, HTML origin model
- Limitation: The cited subsection is informative; normative flag mutations and method checks are distributed through canvas algorithms.

### [Cross-Origin-Embedder-Policy resource isolation](https://html.spec.whatwg.org/#coep)

- Category: `origin-and-isolation`
- Status: `normative`; evidence: `security_control`; confidence: `high`
- Evidence (semantic_summary): Semantic summary: require-corp demands CORS or CORP permission for cross-origin resources, while credentialless omits credentials for cross-origin no-CORS requests.
- Applies when: Documents opting into cross-origin embedder isolation and their subresource fetches.
- Secure default: The default unsafe-none does not require resource-owner permission; stronger isolation is explicit opt-in.
- Failure or exception: Non-permitted resource loads are blocked by Fetch integration.
- Explicit exceptions: credentialless permits no-CORS resources without CORP by omitting credentials; navigations and integration-specific paths differ.
- Dependencies: Fetch CORS, Fetch CORP, Private Network Access, Opaque Response Blocking
- Limitation: The standard warns that credentialless without related protections can expose non-public resources through the client's network position.

### [Cross-Origin-Opener-Policy browsing-context isolation](https://html.spec.whatwg.org/#cross-origin-opener-policies)

- Category: `origin-and-isolation`
- Status: `normative`; evidence: `security_control`; confidence: `high`
- Evidence (semantic_summary): Semantic summary: COOP response policy can force top-level documents into separate browsing context groups and sever unsafe opener relationships.
- Applies when: Top-level navigation responses and opener relationships.
- Secure default: The default unsafe-none policy preserves legacy opener relationships; isolation requires explicit policy.
- Failure or exception: A policy mismatch triggers a browsing-context group switch and proxy severing rather than a JavaScript exception.
- Explicit exceptions: same-origin-allow-popups and reporting-only modes intentionally retain or only report some relationships.
- Dependencies: Fetch response headers, HTML origin model, Reporting
- Limitation: COOP alone does not grant cross-origin isolated capability; COEP and platform support are also relevant.

### [Restricted meta-delivered Content Security Policy](https://html.spec.whatwg.org/#pragma-directives)

- Category: `content-and-type-safety`
- Status: `normative`; evidence: `security_control`; confidence: `high`
- Evidence (semantic_summary): Semantic summary: meta http-equiv can deliver CSP but cannot carry report-uri, frame-ancestors, or sandbox directives, avoiding misleading or ineffective policy placement.
- Applies when: Content Security Policy supplied through an HTML meta element.
- Secure default: Unsupported directives in meta are not accepted as equivalent to response-header policy.
- Failure or exception: The CSP integration ignores prohibited directives according to the CSP algorithm.
- Explicit exceptions: HTTP response headers can carry the directives that meta delivery forbids.
- Dependencies: Content Security Policy
- Limitation: Meta CSP has additional timing and placement constraints defined by HTML and CSP.

### [Origin as the primary web security boundary](https://html.spec.whatwg.org/#writing-secure-applications-with-html)

- Category: `origin-and-isolation`
- Status: `informative`; evidence: `security_rationale`; confidence: `high`
- Evidence (semantic_summary): Semantic summary: HTML directs security decisions and untrusted-content separation around origins, not merely hosts or sites.
- Applies when: Web application architecture and specification integration involving mutually distrusting content.
- Secure default: Same-origin access is privileged; cross-origin access requires a defined relaxation or communication mechanism.
- Failure or exception: Dependent algorithms deny, filter, or isolate cross-origin operations.
- Explicit exceptions: Explicit mechanisms such as CORS, postMessage, document.domain legacy behavior, and policy delegation alter specific boundaries.
- Dependencies: URL origin, Fetch CORS
- Limitation: This section is design guidance; specific enforcement lives in individual algorithms.

### [Sandboxing flag set](https://html.spec.whatwg.org/#sandboxing)

- Category: `origin-and-isolation`
- Status: `normative`; evidence: `security_control`; confidence: `high`
- Evidence (semantic_summary): Semantic summary: HTML defines flags that restrict origin, scripts, navigation, forms, downloads, popups, presentation, and other capabilities in sandboxed content.
- Applies when: Sandboxed iframe documents, CSP sandboxing, and other integrations that create a sandboxing flag set.
- Secure default: An empty sandbox token list applies the full restriction set; tokens selectively lift named restrictions.
- Failure or exception: Prohibited operations are blocked, ignored, or fail according to their integrating algorithm.
- Explicit exceptions: `allow-*` tokens, ancestor policies, and separately defined user-activation paths can relax individual flags.
- Dependencies: CSP sandbox, Permissions Policy
- Limitation: Combining `allow-scripts` and `allow-same-origin` with same-origin content can undermine iframe sandbox containment.

### [Transient and sticky user activation state](https://html.spec.whatwg.org/#tracking-user-activation)

- Category: `user-intent-and-visibility`
- Status: `normative`; evidence: `security_control`; confidence: `high`
- Evidence (semantic_summary): Semantic summary: HTML supplies timestamped transient/sticky activation state, consumption, and propagation algorithms for APIs that require recent user interaction.
- Applies when: Powerful or disruptive API operations that integrate with HTML user activation.
- Secure default: No activation exists until a qualifying trusted input event; transient activation expires and can be consumed.
- Failure or exception: The integrating API denies, rejects, or ignores the operation when activation is absent.
- Explicit exceptions: APIs choose sticky versus transient activation and define any alternative triggers.
- Dependencies: UI Events
- Limitation: Activation indicates event provenance and freshness, not informed consent.

## MIME Sniffing

### [No scriptable MIME promotion from mislabeled binary data](https://mimesniff.spec.whatwg.org/#sniffing-a-mislabeled-binary-resource)

- Category: `content-and-type-safety`
- Status: `normative`; evidence: `security_control`; confidence: `high`
- Evidence (semantic_summary): Semantic summary: text-versus-binary sniffing must never compute a scriptable MIME type because that would enable privilege escalation.
- Applies when: Mislabeled binary-resource sniffing.
- Secure default: The algorithm cannot upgrade a mislabeled binary resource into a scriptable type.
- Failure or exception: A non-scriptable computed type is retained or selected.
- Explicit exceptions: Other explicit script-context and unknown-type algorithms have their own gates.
- Dependencies: none recorded
- Limitation: This guard does not correct unsafe server content placement or all type-confusion risks.

### [No-sniff supplied-type preservation](https://mimesniff.spec.whatwg.org/#determining-the-computed-mime-type-of-a-resource)

- Category: `content-and-type-safety`
- Status: `normative`; evidence: `security_control`; confidence: `high`
- Evidence (semantic_summary): Semantic summary: when the no-sniff flag is set, the computed MIME type remains the supplied MIME type instead of being reinterpreted from content bytes.
- Applies when: Resource processing whose integration sets the MIME Sniffing no-sniff flag.
- Secure default: The flag's default is integration-defined; once set, content sniffing does not override the declared type.
- Failure or exception: Consumers reject an unsuitable supplied type rather than promoting it through sniffing.
- Explicit exceptions: Unknown-type processing and context-specific algorithms differ when no-sniff is unset.
- Dependencies: Fetch X-Content-Type-Options integration
- Limitation: Servers must send an accurate Content-Type and the integration must set no-sniff.

## Notifications API

### [Notifications permission gate](https://notifications.spec.whatwg.org/#permissions-integration)

- Category: `authority-and-permission`
- Status: `normative`; evidence: `security_control`; confidence: `high`
- Evidence (semantic_summary): Semantic summary: notifications are a named powerful feature; constructors and service-worker display algorithms proceed only when permission state is granted.
- Applies when: Creating non-persistent notifications and showing persistent notifications from a service worker.
- Secure default: Non-granted states do not permit notification display.
- Failure or exception: The constructor path fires error and aborts; service-worker showNotification rejects with TypeError.
- Explicit exceptions: Permission state prompt is exposed as the API's default value; user-agent permission policy determines prompting.
- Dependencies: Permissions
- Limitation: Permission does not constrain notification frequency, deception, or content after grant.

## Storage

### [Storage-key segmentation](https://storage.spec.whatwg.org/#storage-keys)

- Category: `storage-and-state`
- Status: `normative`; evidence: `security_control`; confidence: `high`
- Evidence (semantic_summary): Semantic summary: storage sheds segment shelves by storage key; current key equality is based on same-origin and opaque origins fail key acquisition.
- Applies when: Storage endpoints integrated with the Storage Standard.
- Secure default: Different origins do not address the same storage shelf, and opaque origins cannot obtain a key.
- Failure or exception: Return failure for an opaque origin and false for non-same-origin key comparison.
- Explicit exceptions: The storage-key tuple is designed for extension and partitioning can evolve.
- Dependencies: HTML origin model
- Limitation: The current standard text shown here does not itself guarantee additional top-level-site partition dimensions.

### [Persistent-storage permission](https://storage.spec.whatwg.org/#persistence)

- Category: `authority-and-permission`
- Status: `normative`; evidence: `security_control`; confidence: `high`
- Evidence (semantic_summary): Semantic summary: an origin needs the persistent-storage permission before storage can be protected from ordinary user-agent clearing policies.
- Applies when: Requests to mark an origin's storage bucket persistent.
- Secure default: Storage is best-effort until persistence is granted.
- Failure or exception: A denied request leaves the bucket in best-effort mode.
- Explicit exceptions: The origin or user can still participate in clearing persistent storage; quota remains user-agent-defined.
- Dependencies: Permissions
- Limitation: Persistence protects availability, not confidentiality or integrity of stored data.

## URL

### [URL credential validation signal](https://url.spec.whatwg.org/#url-parsing)

- Category: `input-validation-and-failure`
- Status: `normative`; evidence: `security_control`; confidence: `medium`
- Evidence (semantic_summary): Semantic summary: parsing emits an invalid-credentials validation error when username or password syntax appears in disallowed parsing states.
- Applies when: URL parsing integrations that inspect validation errors or separately forbid credential-bearing URLs.
- Secure default: The parser surfaces invalid credential placement instead of silently treating it as ordinary host text.
- Failure or exception: A validation error is reported; parsing can continue unless the integrating API makes it fatal.
- Explicit exceptions: URL validation errors are not generally parse failures.
- Dependencies: none recorded
- Limitation: Integrators needing a hard security boundary must explicitly reject credentials, as Fetch does for Request URLs.

### [Origin-based security decisions](https://url.spec.whatwg.org/#warning-avoid-psl)

- Category: `origin-and-isolation`
- Status: `informative`; evidence: `security_rationale`; confidence: `high`
- Evidence (semantic_summary): Semantic summary: specifications should use origins, not public-suffix or registrable-domain calculations, as hard security boundaries.
- Applies when: Specification design and APIs making authority or isolation decisions from URLs.
- Secure default: Use origin comparison unless a deliberately weaker site relationship is required.
- Failure or exception: Not an algorithm; dependent specifications define denial or isolation.
- Explicit exceptions: Site-based behavior can be appropriate when the weaker trust model is explicit.
- Dependencies: Public Suffix List, HTML origin model
- Limitation: Guidance does not itself enforce origin checks.

## URL Pattern

### [Documented regexp-group restriction hook](https://urlpattern.spec.whatwg.org/#other-specs)

- Category: `resource-and-abuse-control`
- Status: `informative`; evidence: `security_rationale`; confidence: `medium`
- Evidence (semantic_summary): Semantic summary: integrating APIs can forbid regexp groups for security, process-isolation, or performance reasons and should fail early and make the restriction detectable.
- Applies when: Specifications embedding URLPattern in constrained threads, processes, or policy engines.
- Secure default: No restriction is automatic; an integrating API must opt in and document it.
- Failure or exception: The integration should report an error as early as possible, for example by throwing.
- Explicit exceptions: Integrations can allow full regexp groups when their execution environment safely supports them.
- Dependencies: URL, JavaScript regular expressions
- Limitation: This is integration guidance, not a built-in regular-expression complexity bound.

## Web IDL

### [[CrossOriginIsolated] exposure condition](https://webidl.spec.whatwg.org/#CrossOriginIsolated)

- Category: `interface-exposure`
- Status: `normative`; evidence: `security_control`; confidence: `high`
- Evidence (semantic_summary): Semantic summary: annotated constructs are exposed only where the environment's cross-origin isolated capability is true.
- Applies when: APIs requiring process or memory isolation properties represented by cross-origin isolated capability.
- Secure default: The construct is absent until the capability is established.
- Failure or exception: Exposure testing returns false.
- Explicit exceptions: Member-level and interface-level annotations follow inheritance and overload consistency constraints.
- Dependencies: HTML cross-origin isolated capability, HTML COOP, HTML COEP
- Limitation: Actual process architecture is implementation-defined; the capability is the specification-level gate.

### [Sensitive exception-message redaction requirement](https://webidl.spec.whatwg.org/#js-creating-throwing-exceptions)

- Category: `origin-and-isolation`
- Status: `normative`; evidence: `security_control`; confidence: `high`
- Evidence (semantic_summary): Semantic summary: implementations must avoid constructing exception messages that reveal secured, cross-origin, or user-identifying information.
- Applies when: Web IDL exception construction where diagnostic details could cross an information boundary.
- Secure default: Error messages omit sensitive contextual detail.
- Failure or exception: The operation still throws the required exception with a safe message.
- Explicit exceptions: The exact diagnostic text is implementation-defined.
- Dependencies: HTML origin model
- Limitation: Does not prevent side channels from exception type, timing, or observable control flow.

### [Global exposure allowlist](https://webidl.spec.whatwg.org/#Exposed)

- Category: `interface-exposure`
- Status: `normative`; evidence: `security_control`; confidence: `high`
- Evidence (semantic_summary): Semantic summary: [Exposed] limits an interface or member to named global interfaces and intersects member exposure with its host; wildcard exposure is cautioned for capability-bearing APIs.
- Applies when: All Web IDL interfaces, namespaces, and members exposed to Window, Worker, Worklet, or other globals.
- Secure default: Only the declared exposure set is installed; nested exposure sets cannot widen their host.
- Failure or exception: Exposure testing returns false outside the set.
- Explicit exceptions: [Exposed=*] intentionally permits all globals and should be used only when no significant new capability is exposed.
- Dependencies: HTML globals and realms
- Limitation: Exposure controls where an API exists, not who may use an exposed capability.

### [[SecureContext] exposure condition](https://webidl.spec.whatwg.org/#SecureContext)

- Category: `interface-exposure`
- Status: `normative`; evidence: `security_control`; confidence: `high`
- Evidence (semantic_summary): Semantic summary: annotated interfaces or members are exposed only when the relevant settings object is a secure context.
- Applies when: Web APIs whose interface or member carries the [SecureContext] extended attribute.
- Secure default: The construct is not installed in non-secure contexts.
- Failure or exception: Exposure testing returns false; the property is absent rather than callable.
- Explicit exceptions: CrossOriginIsolated is already secure and cannot be redundantly combined on the same construct.
- Dependencies: Secure Contexts, HTML environment settings objects
- Limitation: Secure transport does not imply permission, user intent, or resistance to same-origin compromise.

## WebSockets

### [Restricted WebSocket opening handshake](https://websockets.spec.whatwg.org/#websocket-opening-handshake)

- Category: `network-and-request-policy`
- Status: `normative`; evidence: `security_control`; confidence: `high`
- Evidence (semantic_summary): Semantic summary: the handshake uses Fetch websocket mode with no referrer, no store, service workers disabled, and redirect mode error.
- Applies when: Opening a WebSocket connection from a web environment.
- Secure default: Redirects are not followed and the handshake is not cached or intercepted by service workers.
- Failure or exception: A redirect or failed handshake produces connection failure and closes the WebSocket.
- Explicit exceptions: Credentials mode is include; servers must validate the Origin header and authenticate independently.
- Dependencies: Fetch, The WebSocket Protocol
- Limitation: The browser-side handshake restrictions do not authorize application messages or prevent CSWSH without server Origin validation.

### [WebSocket URL and subprotocol validation](https://websockets.spec.whatwg.org/#interface-definition)

- Category: `input-validation-and-failure`
- Status: `normative`; evidence: `security_control`; confidence: `high`
- Evidence (semantic_summary): Semantic summary: constructors accept only ws/wss (with http/https normalized), reject fragments, and reject duplicate or syntactically invalid subprotocol names.
- Applies when: Constructing a WebSocket object.
- Secure default: Unsupported schemes, fragments, and malformed protocol lists do not reach the handshake.
- Failure or exception: Throw SyntaxError.
- Explicit exceptions: http and https input schemes are normalized to ws and wss.
- Dependencies: URL, The WebSocket Protocol
- Limitation: Syntactic validation does not make ws transport confidential; callers should select wss where confidentiality and server authentication are required.

## XMLHttpRequest

### [Cross-origin credential opt-in](https://xhr.spec.whatwg.org/#the-withcredentials-attribute)

- Category: `network-and-request-policy`
- Status: `normative`; evidence: `security_control`; confidence: `high`
- Evidence (semantic_summary): Semantic summary: cross-origin credentials start false; setting withCredentials true changes the Fetch credentials mode to include.
- Applies when: Cross-origin XMLHttpRequest cookie and HTTP-auth handling.
- Secure default: Cross-origin credentials are excluded and response cookies ignored until explicit script opt-in.
- Failure or exception: Invalid state changes throw InvalidStateError; CORS authorization failures surface as network errors.
- Explicit exceptions: Same-origin credentials behavior is not disabled by withCredentials false.
- Dependencies: Fetch credentials mode, CORS
- Limitation: Opting in client-side still requires correct server CORS policy and does not prevent CSRF.

### [Forbidden request-header guard](https://xhr.spec.whatwg.org/#the-setrequestheader()-method)

- Category: `network-and-request-policy`
- Status: `normative`; evidence: `security_control`; confidence: `high`
- Evidence (semantic_summary): Semantic summary: XMLHttpRequest silently refuses header pairs that Fetch classifies as forbidden.
- Applies when: Script calls to XMLHttpRequest.setRequestHeader().
- Secure default: Security-sensitive headers remain controlled by the user agent.
- Failure or exception: Return without appending the forbidden header.
- Explicit exceptions: CORS-unsafe but non-forbidden headers can be set and may trigger preflight.
- Dependencies: Fetch forbidden request-headers, CORS
- Limitation: The API does not signal the ignored header to script with an exception.

### [Forbidden HTTP method guard](https://xhr.spec.whatwg.org/#the-open()-method)

- Category: `network-and-request-policy`
- Status: `normative`; evidence: `security_control`; confidence: `high`
- Evidence (semantic_summary): Semantic summary: XMLHttpRequest.open rejects methods classified as forbidden by Fetch.
- Applies when: Initializing an XMLHttpRequest with an HTTP method.
- Secure default: Script cannot use XHR to send a forbidden method.
- Failure or exception: Throw SecurityError.
- Explicit exceptions: Allowed methods still undergo Fetch and CORS processing.
- Dependencies: Fetch forbidden methods
- Limitation: Method filtering is not CSRF protection.
