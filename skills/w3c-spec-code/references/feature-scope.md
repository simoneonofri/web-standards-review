
# Feature-scope contract

A browser repository is an implementation environment, not a useful default review boundary. The review boundary is the code that implements the selected specification feature plus the directly supporting code needed to explain its security behaviour.

## Required evidence

Start from concrete entry points and follow repository evidence: calls, data flows, state transitions, policy or permission checks, parsers and serializers, IPC messages, trust-boundary crossings, and security-relevant sinks. Each supporting path must state why it is required and cite the evidence that connects it to the feature.

Do not add a dependency because its name resembles a specification term. Do not broaden to a whole subsystem because one function delegates into it. Stop when the relevant control or sink is understood and record unreviewed dependencies as limitations.

## Engine code

`v8/`, SpiderMonkey, JavaScriptCore, and equivalent engine roots are not feature scopes. A manifest may include specific engine files or a narrowly bounded directory only through `engine_dependencies`, with a concrete reachable path, rationale, and evidence. Reviewing the whole engine requires a separate review objective and explicit authorization.

## Materialization

Run:

```text
python scripts/materialize_pinned_scope.py \
  --repo <implementation-checkout> \
  --manifest <feature-scope.json> \
  --out <isolated-packet>
```

The materializer fails closed on absolute or traversing paths, Git metadata, generic repository or subsystem roots, missing paths, symlinks, non-regular files, unexplained engine paths, and file/byte budget overruns. It writes `feature-scope.lock.json` containing the manifest hash, per-file hashes, and measured packet size.

The lock file is evidence of what was reviewed, not proof that the scope is semantically complete. Reviewers still need to justify the entry points, supporting dependencies, exclusions, and residual uncertainty.
