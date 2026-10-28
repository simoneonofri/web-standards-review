# Concept Boundaries

Use these distinctions before applying framework tables.

## Threat

A threat is a bad event or failure condition that can happen to a model element, stakeholder, policy, deployment assumption, flow, store, process, or trust boundary.

Good form: actor or condition, action or failure, affected element, violated property or interest, consequence.

## Harm

A harm is the negative outcome for people, organizations, ecosystems, or system goals. Harms can motivate threat elicitation, but a harm category is not a threat by itself.

When starting from harms, reason backward to a pathway: which actor, dependency, policy, process, data flow, or governance condition could produce or amplify the harm?

## Weakness

A weakness is why a threat might be possible. Use CWE, OWASP, CAPEC, or implementation vocabularies only when the task has enough design or implementation detail. Otherwise mark the weakness as a hypothesis.

## Control Or Mitigation

A control or mitigation is a possible response. Do not record "missing encryption" or "no consent prompt" as the threat unless the bad event is stated.

## Risk

Risk is prioritization or decision context. Do not score risk unless the user asks for prioritization. Threat elicitation can happen before scoring.

## Prompt Repertoire

A prompt repertoire is a source of categories, questions, examples, or vocabulary. Use it to discover candidate threats; do not use it as evidence that a candidate applies.
