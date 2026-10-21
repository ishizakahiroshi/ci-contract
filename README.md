# CI contract

Canonical JSON, domain hashing, declaration-only check selection, and read-only
Git commit planning for a pinned CI contract.

Python 3.12 or newer. Runtime core uses only the standard library. Structure
validation optionally uses exactly `jsonschema==4.26.0` (the `schema` extra).
No installation is necessary to run the source checkout:

```sh
cd ci-contract
PYTHONPATH=src python -m unittest discover -s tests -v
printf '{"b":2,"a":1}' | PYTHONPATH=src python -m ci_contract canon
PYTHONPATH=src python -m ci_contract canon --kind plan document.json
PYTHONPATH=src python -m ci_contract hash --domain plan document.json
PYTHONPATH=src python -m ci_contract hash --raw payload.bin
PYTHONPATH=src python -m ci_contract hash --canonical --kind plan document.json
PYTHONPATH=src python -m ci_contract validate document.json
```

Each byte-layer command above reads the named file or stdin (`-`, the default);
it never writes a file. `canon` outputs canonical bytes with no final LF. Hash output is lowercase
hex plus LF. `validate` is silent. Errors have fixed diagnostics, with no input
value, filename, traceback, or schema instance echoed. Exit codes: 0 success,
3 invalid input/arguments/schema shape, 9 internal error or missing optional
schema dependency. A 0 from `validate` means structure only, never accepted CI.
`canon` necessarily emits the requested canonical document on success; it is not
a redaction tool. Do not supply secrets. Error paths do not echo that document.

## API and boundaries

- `cjson.loads(bytes_or_str)` strictly parses JSON. Input whitespace is accepted;
  BOM is rejected; negative zero is accepted and serialized as `0`. Escaped
  surrogate pairs are accepted as scalars, unpaired surrogates rejected.
- `cjson.dumps(value)` returns UTF-8 canonical bytes without array normalization.
  `arrays.normalize(value, document_kind=None)` returns a fresh normalized
  value; omitted kind uses the root `kind` when present. Unknown paths/kinds
  preserve array order. Set keys in this pinned schema are strings or canonical
  bytes. No path normalization, casefolding, filesystem inventory, or argv
  execution is performed.
- `hashing.domain_hash(kind, value)` uses a closed top-level projection and array
  normalization. Unknown fields are rejected rather than silently dropped;
  absent fields are not fabricated (schema validation is a separate operation).
  Binding input is the binding object itself, not a request envelope. Inventory
  input is the fixed source-inventory wrapper; `inventory_from_source(source)`
  constructs that wrapper from `source.inputs`. A journal input has
  `payloadKind` and `payloadProjection`, using the pinned typed payload keys.
  Named current-record backlinks alone are excluded. Other hashes remain.
- `hashing.domain_digest(kind, canonical_bytes)` is the low-level nine-domain
  formula for already canonical JSON, without document projection or set
  normalization. This separate API tests the eight partial golden objects,
  which are deliberately not complete schema-valid plan documents.
- `hashing.raw_hash(bytes)` hashes exact bytes. `canonical_hash(value, kind)`
  hashes normalized canonical bytes without a domain prefix. Standalone raw
  objects lacking registered root paths are ordered; provide their complete
  registered document context when set normalization is needed.
- `schema.validate(value)` uses the bundled pinned schema, Draft
  2020-12, explicit FormatChecker, and a registry that refuses external
  retrieval. The fixed schema currently contains no `format` keywords, so this
  does not add real-calendar or expiry checks to its lexical UTC rules.

## Bundled data and reproducibility

Source UTF-8 text is generalized by applying the declared literal replacements
in their declared order, before any JSON subtree is extracted. The bundled
schema preserves the exact transformed UTF-8 bytes, with no parsing or
reserialization step. Array registries, domain projections, and acceptance
fixtures are extracted from the transformed source data.

`src/ci_contract/data/SOURCES.json` records the original source SHA256,
replacement-map SHA256, transformed source SHA256 and byte length, extraction
pointers, and artifact SHA256 and byte length. The replacement map and original
source documents are external build inputs, not bundled runtime inputs. The
manifest excludes its own digest to avoid a self-reference. Test fixtures are
synthetic; source comparisons skip explicitly when either the original input
or its replacement map is unavailable.

## Scope and implementation limits

The implementation includes byte-level operations, declaration-only selection
and graph traversal, literal path validation, read-only Git commit inventory,
and the bounded synthetic-policy plan builder described below. No network
access occurs in these operations.

Execution, native adapters, CI-provider or GitHub connections, credentials,
journal persistence/locking, authority/claim acquisition, semantic result
verification, receipt reuse, worktree inventory scanning, filesystem
source-safety enforcement, publication, and deployment are not implemented.
The planner does not validate real engine attestations. Its result is a plan,
not proof of successful or accepted CI. Individual acceptance projections are
tracked in `tests/acceptance-coverage.json`; they are not end-to-end execution
coverage.

Selection scope groups are `public`, `private`, `github-only`, and `excluded`.
`excluded` is always blocked with `excluded-scope`, including when aliases or
repository-full approval are supplied. Unknown groups are blocked. Repository
scope admission precedes path-specific selection and fallback, so unsupported
repository groups cannot gain admission through a path's ownership rules.
The typed repository's `product: "github-only"` enforces `localAllowed: false`
and `defaultTarget: "github"` through the schema. The scope adapter interprets
that declared product value as the `github-only` scope. These declarations do
not authorize execution.

## Declaration-only selection adapter

`PYTHONPATH=src python -m ci_contract explain planning-input.json` reads a JSON
file, or stdin when omitted / `-`, and emits canonical JSON bytes without a
final newline. Exit 0 means **plan-ready only**, 3 invalid input, 4 blocked.
Malformed JSON or command arguments retain the fixed stderr diagnostic;
well-parsed selection inputs return the structured result (including errors).
No file is written and no checks or git commands are run.

`selection.select(value)` is a pure function returning a fresh result. It accepts
this separate adapter, not any of the eight schema-v1 document kinds:

```json
{
  "model": {
    "components": ["library", "application", "unused"],
    "literalInputOwners": {"src/library.py": "library"},
    "componentInstances": {
      "library": ["library-test-linux"],
      "application": ["app-test-linux", "app-test-windows"],
      "unused": ["unused-test-linux"]
    },
    "guardInstanceIds": ["type", "static", "secrets", "generation"],
    "impactEdges": [["library", "application"]],
    "prepareEdges": [["app-test-linux", "library-test-linux"]]
  },
  "changedPaths": ["src/library.py"],
  "scope": {"repositoryGroup": "public"},
  "baseAvailable": true,
  "repoFullProfileApproved": false,
  "profile": "change"
}
```

Required root fields are `model` and `scope`. Model requires `components`,
`literalInputOwners`, `componentInstances`, `guardInstanceIds`. Optional fields:

- `baseModel`: same shape as `model` (the target). Omitted means the same model
  applies to both revisions. Both graphs, owner maps, guards and obligations are
  retained. With different revisions supply both explicitly; this tool cannot
  discover changes, prove completeness or authenticate the supplied declarations.
- `changedPaths`: distinct canonical repository-relative literal paths, default
  empty. Alternatively `changes` is a list of `{ "status": "add" | "modify" |
  "delete", "path": "..." }` or `{ "status": "rename", "old": "...",
  "new": "..." }`. Do not supply both fields. Rename evaluates both paths;
  deletion retains base owners and base instance obligations. Inputs use `/`
  strings independent of the host OS. NFC, relative nonempty segments, no
  backslash/colon/traversal/control characters, Windows reserved basenames,
  invalid punctuation, trailing dot/space or casefold collisions are
  required; nothing is silently normalized.
- `impactEdges`: producer → consumer pairs. Union closure is finite even with
  cycles. `prepareEdges`: dependent instance → prerequisite instance pairs.
  Preparation is a separate graph; any union preparation cycle is invalid,
  including one outside the selected subgraph. Missing endpoint references are
  invalid. Cycle detection can reject a cyclic declaration before references
  are resolved; it does not certify an otherwise incomplete model.
- `profileInstanceIds`: optional map of profile name to declared instances.
  Non-change profiles (`case`, `integration`, `release`, `operations`) must be
  declared. Entries add required checks, never remove guards or impacted checks.
  Expanded Linux/Windows/features are distinct declared instance IDs; no host
  filtering, variant inference or native execution is performed.
- `pathInstanceIds`: optional map of literal paths to additional declared
  instances (for example package verification). Paths must also have ownership
  rules to support sound component impact closure.
- `requiredInstanceIds`: optional root list of already-declared expanded variant
  IDs to add. Unknown IDs are invalid; this is not a hash/variant ID generator.
- `baseAvailable` defaults true. Missing base or unknown ownership blocks unless
  `repoFullProfileApproved` is true AND a model declares a `full` profile whose
  union covers the entire base/target instance universe. Fallback is confined to
  this repository; there is no other-repository input or discovery mechanism.
- `scope.repositoryGroup` is the normalized registry group (`public`, `private`,
  `github-only`, `excluded`). Optional `requestedAlias` requires an exact entry in
  `scope.aliases`, a map from aliases to canonical groups. An unknown alias,
  conflict with repositoryGroup, unknown group or excluded group blocks. Scope
  registry trust is the caller's responsibility; spelling alone is not trusted.

Unknown fields, duplicate identifiers/edges, malformed types and dangling
references are invalid. A ready result partitions the declared instance universe
into selected and not-selected IDs and supplies a reason for every omitted ID.
Guard IDs are always added; then reached components in declaration order,
path-specific obligations, profiles, explicit required IDs and preparation
closure. Base declaration order precedes target additions. Membership is set-like
with no duplicates. Early blocked/invalid results expose no partial partition.
Evidence lists reached components, evaluated paths and fallback. The standalone
adapter does not construct graph pins, complete plans or repository inventory;
the commit planner wraps it for those operations below. Quality waiver/replacement
semantics, execution, result verification and global ledger hashing remain out
of scope.
No successful empty selection is returned.

The selection tests preserve extracted source cases without changing their
expectations. Status/exit code and the selected set must match exactly;
not-selected IDs are unique, declared examples that must each be absent from
the selection. Cases `c05` and `r08` remain unexecuted because the supplied
acceptance inputs lack the necessary ownership/variant and rename-impact
information, respectively. No missing declarations are invented.

The standalone adapter's `repoFullProfileApproved` and `full` profile behavior
only evaluates caller-supplied declarations. It does not authenticate approval
or add repository-full support to the typed commit planner. See the planner's
repository-full limitation below.

## Read-only commit planning

```sh
PYTHONPATH=src python -m ci_contract plan --repo synthetic --repo-path synthetic.git --base <40-lowercase-hex> --target <40-lowercase-hex> --profile change --out plan.json
```

The schema dependency is needed for planning. Inputs are a local Git object
database and exact commit SHA-1s. Branch names, `HEAD`, short or uppercase hashes,
tags and non-commit objects are rejected. Missing base/target commits block;
the current branch is never substituted. No fetch, checkout, worktree scan,
filter, product/native check command, hook, GitHub request or adapter execution occurs.
Git-directory selection uses filesystem metadata only: if the supplied root has
`.git`, it must be a directory and is the exclusive object database. A `.git`
file blocks on every OS; there is no trailing-dot trick or fallback to root
objects. The supplied root is considered a bare/Git directory only if `.git`
is absent. `--repo-path` must be an explicitly trusted checkout root with trusted
`.git` metadata, or a separately provisioned bare repository whose filesystem is
not controlled by PR contents. Do not pass an arbitrary directory inside a
checkout. No upward discovery occurs, but a directory containing forged HEAD,
refs and objects can look like a bare repository; metadata checks cannot prove
its provenance. No worktree source bytes are read.

### Safe Git resolution

Git is resolved once to an absolute executable from absolute PATH entries.
The exact current directory is excluded, while its descendants remain eligible,
so using the filesystem root as CWD does not exclude every executable. The
repository and its entire subtree remain excluded. Both lexical and resolved
path comparisons are retained; filesystem identity comparisons using `os.stat`
device/inode pairs reject aliases of the exact current directory and repository
root, including paths beneath an alias of that root. Aliases pointing directly
to a repository subdirectory rely on realpath resolution, not the identity
comparison alone.
Candidates whose required filesystem identity cannot be read are skipped
rather than treated as safe. Executable symlinks into excluded locations are
rejected.

Double-quote-containing PATH entries are skipped, not unquoted. On Windows,
every PATH entry beginning with `\\` or `//` is skipped, including UNC and
administrative-share spellings. Windows extended/device prefixes `\\?\` and
`\\.\`, including forward-slash or resolved aliases, are also skipped before
trust comparisons. If CWD or the repository root itself has a device/extended
prefix in its raw, absolute or resolved identity, resolution blocks with
`git-unavailable`. Such root spellings are unsupported rather than compared
against ordinary aliases.

Identity checks supplement spelling checks for aliases such as symlinks,
junctions, and drive aliases; they depend on the filesystem's reported identity.
They are not a claim of native coverage for every alias mechanism or a defense
against concurrent filesystem replacement. Synthetic symlink/junction tests run
where their platform supports creating them, and otherwise report a skip. No
native `subst` test coverage is claimed.

Missing safe Git is `git-unavailable`; missing repository is
`repository-unavailable`; missing commits retain their side-specific reasons.
Tests use this same safe absolute resolver, including fixture Git writers.
Every returned blob is checked against its Git SHA-1 object ID as well as the
inventory's raw SHA256. Raw tree objects are not independently OID-rehashed.
`.git`/`git~1` path aliases are rejected, including Git's HFS-ignored characters
U+200C–200F, U+202A–202E, U+206A–206F and U+FEFF inserted into `.git`.

### Trusted base controls

The trusted base must contain:

- `.ci/manifest.json`: schema-v1 manifest, complete declared literal input model
  and logical checks/variants, repository ID matching `--repo`
- `.ci/quality-projection.json`: canonical schema-v1 repository projection,
  unambiguous external requirement/check mappings consistent with the manifest
- `.ci/policy.json`: the deliberately bounded synthetic policy format shown in
  `tests/fixtures/synthetic-policy.json`; unknown dialects and exceptions block
- `.ci/engine.lock.json`: schema-v1 engine lock matching the manifest and this
  package's schema bytes; fixture `synthetic-engine-lock.json` labels every
  unavailable real engine/bundle/attestation input as synthetic

There is no implicit default policy or engine identity. The synthetic manifest
template has a placeholder quality commit; the test helper `synthetic_history`
replaces it with an actual earlier synthetic commit. The manifest's exact
quality reference is retained in the plan and embedded selection request after
verifying its raw blob equals the base projection and its anchor is a recoverable
ancestor of base. No self-referential commit hash is invented.

### Bounded quality-reference ancestry

Ancestry is established from authenticated raw commit parent bytes through one
live binary `cat-file --batch` process. Replacement refs, grafts, and shallow
history cannot fabricate the relationship. Search is bounded to 256 parent
edges in depth, 10,000 distinct discovered/queued commits including base,
10,000 commit reads, and 1 MiB per commit payload. A valid commit with an
oversized message also exceeds the payload bound.

The fixed depth limit of 256 is a resource budget for this trust proof, not a
claim that a repository's history has at most 256 commits. It prevents an old
reference from requiring an arbitrarily long walk. The independent discovered
commit, read-count, and payload bounds also constrain wide merge histories,
queue size, and object-processing cost. The depth limit remains 256; a longer
history does not silently raise it or authorize a shallower trust check.

If the anchor cannot be established within these bounds, planning fails closed
with `projection-ancestry-limit-exceeded` and exit status 4. It does not accept
an unproved relationship, substitute another reference, or emit a ready plan.
Missing anchors, unrelated anchors, unavailable ancestry, and an ancestor
missing its projection have distinct blocked reasons when the corresponding
condition can be established within the bounds. Missing target manifest or
projection is distinguished from missing base controls.

When a trusted quality reference is too old to establish ancestry within these
limits, every PR planned against that trusted base is blocked, irrespective of
which files the PR changes. The reanchoring PR itself is also blocked when
planned against that expired trusted base. Recover by an approved reanchoring of the trusted
base controls:

1. Identify a recent, recoverable ancestor commit within the bounded ancestry
   of the base to be adopted. That commit must already contain the same canonical
   quality-projection bytes as the trusted projection, byte for byte.
2. Verify the candidate projection's canonical bytes and digest against the
   current trusted projection. Reanchoring must not weaken or rewrite quality
   requirements. A changed projection needs its own review and approval.
3. Through the approved control-update process, set the manifest's
   `qualityProjectionRef.commit` to the recent ancestor and
   `qualityProjectionRef.sha256` to the verified raw digest. Identical projection
   bytes retain the same digest value. Update and check all affected pins for
   consistency before adopting the updated trusted base.
4. Confirm ancestry and byte-pin validation succeed against that base before
   resuming PR planning. A PR's target-side reference change alone cannot
   replace the trusted base controls.

Reanchoring is an operator procedure, not an automatic fallback implemented by
this planner. It also does not override the independent count or payload bounds.

### Selection and trust

The planner expands typed variants and hashes their canonical identities,
compiles variant/profile/multi-owner literal impact rules into the selector,
adds base guards and preparation closure, then embeds complete selected check
definitions.
All variants of a declared prerequisite are conservatively retained. Declared
inactive-profile instances have omission reasons. All tracked input files must
have literal rules; unknown inputs or incomplete models block. Target ownership,
impact edges and check mappings can broaden the base graph. New target components
may reach existing base checks. Only base check definitions, variants, guards,
preparation dependencies, requirements, roles for existing paths and policy are
authoritative. Target-only checks/variants appear in omission reasons, never as
executable definitions. Target removals cannot narrow the graph union. Evidence
hashes the actual normalized target graph separately; rename is deletion plus
addition and reaches both owners. Directory roles are preserved for literal
directory entries; a directory rule is not an implicit recursive file owner.

Every changed path absent from active base literal ownership is unknown, even
when target assigns it to an existing component. For each such path separately,
union impact reachability must identify a base-known component; its trusted
`broadLogicalCheckIds` expand to applicable base variants plus guards/preparation,
with `component-broad` fallback evidence. Target-only components without that bridge,
unrelated changed paths and global guards alone cannot certify the unknown path.
A direct known-component assignment also uses this explicit broad fallback.
Non-guard broad instances must be active in trusted base mappings for the current
profile. Component guards count only for their declared components and profiles;
inactive or out-of-scope guards cannot provide unknown-path coverage.

A new target path assigned directly to a base-known component remains eligible
for this broad fallback and can produce `plan-ready`. This is intentional current
behavior: the target declaration can identify which trusted component's broad
checks to select, but it is not independent proof that those checks fully cover
the new path. Adoption in a real repository requires a required-check aggregator
that independently recomputes necessary obligations from the trusted base and
enforces them against reported results. That aggregator is not implemented.
The current planner alone must not be treated as that independent enforcement
boundary.

### Repository-full fallback limitation

The selection core's `profileInstanceIds.full` remains unchanged, but cannot be reached from a schema-valid manifest: the fixed profile enum excludes `full`, and `selectionModel` rejects additional properties and has no repository-wide set field.
Repository-full fallback remains unimplemented in this planner and is deferred to the request stage; no synthetic-policy approval fields are added, and paths that cannot reach a known component remain blocked.

Unresolved paths block with `unknown-path-no-approved-fallback`,
`unknown-target-owner-no-approved-fallback`, or
`unknown-path-no-trusted-broad-checks` as appropriate. The excluded scope remains
blocked regardless of approval or aliases.

### Quality comparison and output

Target quality comparison rejects removed requirements/references/check mappings,
removed provenance origins, releaseRequired true→false, narrowed applicability,
retargeted requirements, and added exemptions. Purpose/revision/approval text and
coverage/classification labels can change because these descriptive fields do not
control execution; no unsupported strength order is invented. Requirement
checkIds/externalReferences/origins and mapping logicalCheckIds may grow;
applicability may remain equal or broaden to all. Added references must resolve
unambiguously. Base obligations and pins remain authoritative for this plan.

The output contains fixed source inventory, raw byte and domain hashes, typed
changed selection request/pins and selection evidence. File bytes are never
newline-translated. Parent directories and explicit empty Git trees are included;
empty-directory-only changes affect the inventory/digest but have no file delta.
No execution destination, run ID, time or authority is added. The schema-required
repository.defaultTarget is only the trusted repository preference. A future
`execute` must require an explicit `--target`; it must never fill an omitted
execution target from `defaultTarget`. Validation/comparison of target manifest,
policy and engine-lock changes as proposed control updates remains a later stage;
reading the target reachability graph here does not approve those updates.

`selectionEvidence.completenessVerified` remains false: structural references
and literal path coverage are checked, but synthetic graph generator/review
attestations and compatibility/revocation registries are not authenticated here.
Plan-ready is not an accepted result, a trusted engine installation, or proof
that any check ran. No global ledger is an input.

On success, `--out` receives schema-validated canonical UTF-8 JSON without LF,
and stdout receives its plan domain hash plus LF. Existing files/symlinks are
never overwritten; a failed new write/close or stdout digest write/short-write/
flush is cleaned up, preserving any preexisting file. Source blobs are read in
one `cat-file --batch` process per inventory after the 10,000-entry bound is
checked, including explicit directories. Exit status is
0=plan-ready, 3=invalid input, 4=blocked, 9=internal error. Errors emit only fixed
binary diagnostics to stderr. No input value, raw Git error or local path is
echoed. Missing inputs block; malformed controls, unsupported source paths,
links/submodules/LFS, and inconsistent byte pins are invalid input. No request
reconstruction/stale execution state is implemented in this planning-only slice.

## Test boundaries

Tests create bare synthetic repositories only inside temporary directories,
using fixed author/time/settings and `hash-object`, `mktree`, and `commit-tree`.
They do not read real project repositories or execute product checks.
`SOURCES.json` records synthetic SHA256 labels, their exact UTF-8 bytes, and
fixture JSON pointers. Original-source comparison tests require the external
source input and replacement map, apply the same ordered literal transformation,
and skip explicitly if either is absent. Platform emulation tests do not imply
a native Windows run, and platform-specific skips are not successful execution
of the skipped test.

## M5: verify a supplied plan, execution and result

`ci-contract verify --plan plan.json --execution execution.json --result result.json`
reads exactly these three JSON documents. It writes one ASCII status line with an
LF terminator to stdout, returns the §2 exit code, and emits only fixed diagnostics
to stderr. It does not write a result, run checks, contact a provider, discover a
worktree, create an authority, or implement request/execute/aggregation.

The pure `ci_contract.verify.verify` function checks all three document structures
and lexical rules before semantic or terminal decisions. It binds the canonical
plan and execution identities, exact instance sets (including OS variants), source
inventory, required case and analysis-target sets, adapter identity, payloads,
selected attempt, and independently observed completion and cleanup. Acceptance
is only for the supplied plan's scope, never a PR-wide success declaration.

A trusted collector is not implemented. Until it is, the three-document CLI cannot
return accepted (0) for a result requiring proof. Embedded proof, matching hashes,
and an artifact origin are self-claims, not independent backing; without backing
it returns blocked (4), including an unsupported terminal claim. No collector CLI
option is provided. Only core tests explicitly injecting a separate synthetic
collector ledger can return accepted. Cases r13 and r14 exercise that core-only
acceptance. Synthetic terminal observations exercise cancelled (6), timeout (7),
and unknown (8); a late older success cannot replace the selected attempt's
observed timeout. The synthetic ledger is a test boundary, not production trust.

Skipped required cases remain blocked because skip approval is not implemented.
Type/static/secrets require completed analysis of a nonempty planned target set;
zero diagnostics is not confused with zero tests or zero targets. Structural
errors return invalid-input (3) before these decisions, without trimming values.

## Typed selection requests (M6)

The pure request builder takes a schema-v1 selectionRequest and independently
supplied fixed control references and raw bytes. It validates all available
input shapes before admission decisions. Unknown fields, duplicate IDs, invalid
paths, more than 256 requested checks or case selections, and normalized UTF-8
larger than 16 KiB are invalid (3), without truncation. Missing fixed references
are blocked (4); different fixed bytes are stale (5).

changed preserves the existing planner's bytes. explicit resolves declared
logical or instance IDs and declared test case IDs, retaining mandatory guards
and the complete native check command/case set. full is the explicit repository
wide request: it includes every instance declared by the trusted base, including
all OS variants and mandatory guards. Target-only checks and variants are
recorded as deferred omissionReasons, never executable definitions. The raw
target-only definitions need not have executable mappings or known requirements:
changed, explicit and full defer them consistently. Base quality validation and
rejection of reduced existing target obligations remain in force. It does not automatically
replace a blocked changed request or extend into another repository. A caller
can supply an independent repository_group; excluded or conflicting scope is
blocked. Unsupported declared profiles remain blocked by the selection core.

### 解釈した点

The confirmed trust boundary keeps expectedPins as comparison-only values, not
as trusted input locations: reading a requested commit and matching its hash
cannot establish trust.

plan accepts --selection instead of --base. A non-null selection base uses the
existing fixed-base Git trust boundary. expectedPins never chooses a replacement
policy or engine. The pure API supports a null base with separately supplied
trusted controls. The CLI cannot bootstrap that trust from request-supplied pins,
so a null base is blocked until a separate trusted anchor is specified. Invalid
request shapes still return 3 first. Both explicit and full with a null base
return blocked (4), only the fixed diagnostic, and leave no output file. With a
base, changed, explicit and full read trusted controls from that base commit
through the existing M3 path and compare the pins. K7 full is checked through
that CLI path as well as the pure core. A ready plan is not a test success.

Pure preflight rejects a snapshot GitHub request, disallowed local execution,
and an unavailable quality projection before creating any execution document or
starting a process. Dispatch helpers only construct/restore the six fixed input
fields and reconstruct the plan; they do not dispatch anything.
reconstruct_bound_dispatch additionally requires an independently supplied
request binding and compares request ID, workflow revision and plan hash. It
also requires target github and shares plan-derived repository ID, source digest,
selection request digest, engine-lock digest and profile checks with verify.
The unbound reconstruct_dispatch helper proves only plan reconstruction and is
not a complete dispatch authorization check. selection_json must equal its
canonical UTF-8 bytes exactly.

request_binding constructs the fixed request-binding and scope domain hashes.
verify optionally accepts an independent binding in the Python API; its existing
CLI still has only plan, execution and result inputs. Synthetic collector tests
supply independent workflow and target observations. A workflow_dispatch result
accepted by this verifier does not satisfy a PR required gate. No claim, journal,
lease, native authority, provider connection or executor is implemented.

## Existing checkout line endings

Text files are normalized to LF in the index and on checkout, including when
core.autocrlf=true. A clone checked out before these attributes were added may
retain earlier line endings until checkout is refreshed. Preserve local edits
separately before using a fresh checkout, or review normalization changes from
git add --renormalize . before committing. Do not discard local edits merely to
refresh line endings.
