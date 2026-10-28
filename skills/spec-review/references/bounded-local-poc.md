# Bounded Local Proof of Concept

Create a PoC only when it materially clarifies a disputed mechanism, process condition, model consequence, or feature composition and the test can remain local. A PoC supports the evidence packet; it is not automatically part of the public reply.

## PoC class and verification scope

Choose exactly one class and do not silently replace unavailable implementation evidence with a simulation:

- `executable`: a deterministic local program exercises an implementation or library behavior.
- `browser`: a loopback-only page exercises behavior in an identified browser build.
- `documentary`: a deterministic check evaluates a specification, charter, issue, or other preserved source artifact.
- `model`: a deterministic state machine or protocol model tests the consequence of stated assumptions without claiming implementation behavior.

Choose exactly one primary verification scope: `specification_mechanism`, `process_condition`, `model_consequence`, or `implementation_behavior`. Documentary and model PoCs must not claim `implementation_behavior`. When required browser, hardware, credential, network, or implementation access is unavailable, record `unable_to_verify`; do not promote a mock or model to implementation evidence.

## Safety boundary

- Bind servers explicitly to `127.0.0.1`; never use a public interface.
- Use synthetic pages, fake secrets, and disposable identifiers.
- Load no external scripts, fonts, images, stylesheets, endpoints, or credentials.
- Send observations only to a loopback endpoint owned by the PoC.
- Do not scan, crawl, authenticate to, or modify a live service.
- Do not publish, upload, commit, or attach the PoC unless the user explicitly requests the exact publication.

## Required controls

Include three independently observable cases adapted to the selected class:

1. A positive case in which all stated prerequisites hold and the expected local observation occurs.
2. A negative case that differs in the security-relevant condition and produces no observation.
3. A mitigated case that enables the mitigation being claimed and produces no observation.

Record the expected and observed result for every case. A `verified` PoC requires all three cases to pass. If a control fails or cannot run, report `not_reproduced` or `unable_to_verify` and do not use the PoC as support for the corresponding claim.

## Machine-readable evidence and validation

Create `poc-evidence.json` beside the PoC README and validate it with `scripts/validate_poc.py`. The evidence must record the PoC class, verification scope, environment, exact command, three case results, bounded claims, stable concept identifier, and SHA-256 digests for every cited local artifact. It must also confirm synthetic inputs, absence of real credentials and external endpoints, and loopback binding for browser and executable servers.

The validator establishes completeness and artifact integrity; it does not establish that the security conclusion is correct. Preserve command output and environment identifiers so a reviewer can rerun the check.

## Cross-standard propagation

After a PoC verifies a reusable concept, assign a stable `concept_id` and examine every specification in the active review set. For each target record one of `applicable`, `not_applicable`, `already_covered`, or `unable_to_verify`, together with target-specific evidence. Similar wording or a shared API shape is only a routing signal; it is not a finding until the target's own evidence and threat path establish the issue.

## README contract

The PoC README must state:

- prerequisites and exact local run command;
- PoC class, verification scope, environment identity, and verification status;
- loopback URLs and files involved;
- expected positive, negative, and mitigated results;
- what the PoC demonstrates;
- what it does not demonstrate, including any same-origin, injection, browser-support, user-interaction, or deployment assumptions;
- artifact hashes, the stable concept identifier, and the cross-standard applicability matrix or its local path;
- how to stop the server and remove temporary data.

Keep claims at the demonstrated layer. A local composition test does not by itself prove cross-origin access, real-world exploitability, implementation conformance, prevalence, or bypass of a platform security boundary.
