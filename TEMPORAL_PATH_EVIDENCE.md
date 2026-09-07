# Temporal path evidence and identity confidence

Two derived counterexamples reproduce incorrect path enrichment: a later renamed path replaces the path recorded by the syscall spanning an earlier Read, and an Exact inode edge upgrades a separately looked-up path to Exact FilePath. These are synthetic variations of a verbatim physical capture subset; they are not physical rename validation.

The graph now prefers compatible identity evidence from the same task/operation spanning the origin timestamp. Nearby evidence is used only when the available nonempty paths agree. Conflicting paths remain unresolved. Pathless observations cannot shadow existing nonempty evidence.

An inferred_path_snapshot evidence marker preserves the raw identity edge confidence while limiting FilePath origin views to Probable. A directly recorded request-origin path retains its original causal confidence. No origin session NDJSON is modified.

Regression coverage includes later rename, pathless tail, conflicting names without a contemporaneous syscall, exact identity with inferred path, directly recorded Exact path, and no path evidence. The older graph test now asserts Exact identity edges separately from inferred Probable paths; a remaining pathless origin keeps the request Unresolved.

Physical capture acceptance, all visible graph interactions, and intermittent native startup access violations remain open.
