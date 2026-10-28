# What Are We Building: L0, L1, and L2

The portable `what-are-we-building` projection remains pinned to its reviewed
component source. The bundle adds one explicit integration contract for the
level of model needed by a specification review. This avoids silently changing
the component contract while making the reusable workflow visible.

## L0 — generic context

Start from the pinned architecture, explainer, use scenario, or system
description. Keep the target capability as a black box where that is enough to
show the user, other affected people, main principals, minimum directional
flows, and first authority or trust boundaries.

The L0 model should not contain WebIDL conversion, numbered algorithm steps,
renderer or browser-process decomposition, IPC, implementation stores, or
engine-specific assumptions. Its exit artifact is a high-level
`model-packet/v1` plus an authoritative DFD and `dfd-dictionary/v1`, with the
deferred detail recorded explicitly.

## L1 — specification and API surface

Open the L0 black box through the Web-exposed API. Inventory interfaces,
operations, attributes, dictionaries, callbacks, relevant return types,
exposure gates, normative state, lifecycle relationships, and the principals,
documents, or origins to which behavior is attributed.

A method with meaningful behavior may become a stable logical process.
Dictionaries remain typed data contracts carried by flows or retained in
state; they are not automatically processes. The L1 exit artifact is a
`webidl-api-surface-inventory/v1` or equivalent model refinement with stable
links to its L0 parent elements.

## L2 — normative algorithm child analysis

Select one L1 operation and preserve its parent process identity. The first
child phase is always **Phase 0: WebIDL exposure and argument conversion before
the first numbered algorithm step**. Record conversion order, required members,
getters, proxies, iterators, string conversion, callback validation,
promise-returning behavior, conversion failures, and observable side effects.

Then group the numbered normative steps into ordered subprocesses without
silently dropping or reordering behavior. For each subprocess record the
executor, inputs and state, state transition, delegated algorithm, security
property, precondition or default, exception, failure behavior, residual or
non-guarantee, DFD mapping, and test or PoC decision.

The exit artifact is an `algorithm-analysis/v1` plus a child DFD. Child IDs are
local to the child view. They do not rename the L1 parent or retroactively
change an accepted L0 model.

## Implementation mapping

Implementation mapping remains a separate child view. Renderer state,
browser-side registries, IPC, dispatch, feature flags, and implementation
stores can add evidence about a concrete implementation, but cannot redefine
the specification-level identities or boundaries.

## Completion

The selected level is sufficient when it supports the current review decision
and makes important threats traceable. Schema validation proves the wire
contract; it does not prove methodological completeness or authorize
publication.

The versioned machine-readable contract is `contracts/model-abstraction-ladder-v1.json`.
