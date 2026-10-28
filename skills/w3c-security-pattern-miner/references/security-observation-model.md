# Security Observation Model

An observation is atomic and evidence-oriented. Supported `observation_type` values are `asset`, `actor`, `component`, `entry-point`, `trust-boundary`, `attacker-capability`, `security-requirement`, `security-guarantee`, `security-mechanism`, `prohibition`, `assumption`, `threat`, `failure-mode`, `attack-surface`, `residual-risk`, `implementation-obligation`, `operational-obligation`, `testable-behavior`, and `unresolved-question`.

Required fields include `observation_id`, `spec_id`, `spec_version`, `observation_type`, `statement`, `security_category`, `security_properties`, `actors`, `assets`, `trust_boundaries`, `applicability`, `evidence_class`, `evidence`, `confidence`, and `open_questions`. Confirmed non-hypothesis observations require evidence.