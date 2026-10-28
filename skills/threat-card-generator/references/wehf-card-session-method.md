# WEHF Card Session Method

Use this reference when designing W3C Web API, specification-review, or workshop cards from the WEHF Web Security Model deck pattern.

Source: `W3C - Web Security Model @ WEHF 2026`, Simone Onofri and Giovanni Corti, June 2026 deck.

## Deck Lessons

Cards are prompts for Shostack's second question, not a replacement for the full method. The WEHF workflow assumes a model exists first:

1. Draw the DFD.
2. Add trust boundaries.
3. Create a dictionary.
4. Select a lens such as STRIDE.
5. Walk elements and interactions.
6. Write threats as stories.
7. Go broad before deep.
8. Map responses and remaining threats later.

## Card Design Implications

For W3C Web API decks:

- require each card to name or point to a model element, flow, store, external entity, trust boundary crossing, permission decision, policy gate, lifecycle gate, or implementation/deployment assumption;
- write prompts that produce a threat story, not only a category label;
- prefer "could..." questions that players can answer from the diagram and dictionary;
- include `outputs` that capture affected element, threat story, affected stakeholder or property, response hint, assumption, and remaining question;
- include cards for inline safeguards when useful: active-document checks, allowed-use checks, secure-context checks, visibility/lifecycle checks, permission checks, cached state, error surfaces, rate limits, revocation UI, and delegated implementation responsibilities.

## Session Discipline

Use broad-before-deep coverage. A deck should help teams inspect the whole model before following one advanced attack path too deeply.

If cards repeatedly produce abstract discussion, require the player to rewrite the answer as:

`As [actor or condition], I can [action or failure] at [model element or flow], causing [violated property or affected interest], unless [response or assumption] holds.`

Use the Geolocation example as a pattern for turning diagram elements into prompts. Do not use its threats or responses as facts for another specification.
