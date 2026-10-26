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

Execution on GitHub, native adapters other than the local Python adapter
protocol, CI-provider or GitHub connections, credentials, native
(github-run-v1) authority, receipt reuse, a sandbox for local checks,
publication, and deployment are not implemented. The local single-supervisor
journal and claim core of M7 (below) sends nothing by itself; M8 runs checks on
this computer only through `execute --target local` (last section).
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

In the pure builder (`build_selection_plan`, and `reconstruct_dispatch` which
calls it) `changes` is the trusted caller's declaration, like the two source
inventories and the controls. Its shape, paths and uniqueness are validated, but
it is not compared with the difference of the two inventories: a caller that
leaves out a changed path gets a plan that selects less, one that declares an
unchanged path gets a plan that selects more. `fixed_inputs_from_git` derives the
inventories and the changes from the same two commits, so they agree there. A
reconstruction rebuilds from the same caller-supplied `changes`; it detects
a different declaration (the plan hash covers `selectionEvidence.changes`), it
does not make the declaration independent.

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
canonical UTF-8 bytes exactly. Since M7, reconstruct_bound_dispatch is a helper
only and not a dispatch authorization: the execution-side dispatch boundary is
ci_contract.claim.dispatch, which calls it and then checks the journal.

request_binding constructs the fixed request-binding and scope domain hashes.
verify optionally accepts an independent binding in the Python API; its existing
CLI still has only plan, execution and result inputs. Synthetic collector tests
supply independent workflow and target observations. A workflow_dispatch result
accepted by this verifier does not satisfy a PR required gate. M6 itself adds no
claim, journal or lease; M7 adds the local journal and claim core below. No
native authority, provider connection or executor is implemented.

## M7: local authority journal and claim

`ci_contract.journal` and `ci_contract.claim` implement the local side of F05
for `local-single-supervisor-v1` only. There is no CLI command for them. They do
not contact a provider, read a worktree or start a process: the caller supplies
the clock, the sender and a read-only query. Tests supply synthetic ones.

### Placement

`LocalJournal.create(path, authority_id=..., repository_roots=[...])` creates an
empty file at the explicit path (mode 0600 on POSIX; Windows ACLs are inherited
and not checked). There is no default location, and the directory must already
exist. Every transaction checks the placement again and blocks (4) with a fixed
reason code for: a relative path; UNC, extended or device prefixes, reserved
device names or stream syntax; a remote or non-fixed Windows drive; a missing
directory; a journal or lock entry that is a link, reparse point or hardlink; a
location at or below a supplied repository root (compared case-insensitively on
Windows after resolution, and by filesystem identity of every ancestor, so
separator spelling and directory aliases do not matter); and, on POSIX, a
directory or existing entry owned by another user or writable by group or
other. Cloud-synchronized folders cannot be identified through these queries
and are not claimed to be detected. Malformed arguments are invalid input (3).

### Records

Each line is ci-cjson-v1 canonical bytes followed by LF, with the closed keys
sequence, fence, previousRecordSha256 (null for the first record), recordType,
payloadKind, payloadProjection and recordSha256. recordSha256 is the pinned
`journal-record` domain hash; the current-record backlinks
(`claim.ledgerSequence`, `claim.ledgerRecordSha256`,
`attemptAuthority.adoptionRecordSha256`) point to the record itself. The hash
covers the header keys and the typed payload projection, excluding only
recordSha256 and the two hash backlinks.

| Record type | Payload kind |
|---|---|
| request, retry-approval | requestBinding |
| claim-acquired, claim-coalesced, claim-heartbeat, claim-orphaned, claim-closed, submit-unknown | claim (localSupervisorClaim) |
| adoption | attemptAuthority |
| receipt, receipt-conflict | result |

The fence increases by one only on claim-acquired. A sequence gap, a chain or
record hash mismatch, a non-canonical record, an invalid payload, a wrong
backlink or fence, a duplicate request record, or a last line without LF makes
the journal unverifiable: operations return unknown (8), nothing is acquired or
sent, and nothing is repaired, truncated or renumbered. A reordering that is
re-signed consistently is not claimed to be detectable. One journal belongs to
one authority: a request binding, claim or adoption that names another authority
ID also makes the journal unknown (8, `journal-authority-mismatch`) before any
decision is taken, so the same file opened under another ID never coalesces.

### Locking and durability

A transaction opens `<journal>.lock`, takes an exclusive OS advisory lock
(Windows `msvcrt.locking` on byte 0, up to six calls of about ten seconds each,
then blocked with `journal-lock-unavailable`; POSIX `fcntl.flock`, which waits),
re-reads and verifies every record, reads the clock once, decides, appends with
unbuffered writes and syncs every record (Windows FlushFileBuffers, POSIX fsync,
plus a POSIX directory fsync on creation) before it returns. A failed write or
sync is unknown (8), never a success. The lock file's existence is not evidence
of acquisition. The POSIX branches are not executed by a Windows test run.

### Anchor

`LocalJournal.create(..., anchor_path=...)` and `LocalJournal(..., anchor_path=...)`
add an anchor: one canonical JSON file at a second explicit path with the keys
kind (`ci-contract-journal-anchor`), version (1), authorityId, journal (the
resolved journal path), sequence (the number of records) and recordSha256 (the
last record's hash, null for an empty journal). The anchor path follows the
journal's placement rules (reason codes with the `journal-anchor-` prefix) and
must be in another directory than the journal (`journal-anchor-same-directory`),
so one restored or synchronized folder cannot take both back together.

After every synced append the anchor is replaced by a synced new file. Under the
lock, every transaction compares the journal with the anchor:

| Journal against the anchor | Verdict |
|---|---|
| exactly at the anchor | continues |
| one record past the anchor (a crash between the two writes) | the anchor is caught up, then continues |
| fewer records (trailing records removed, an older copy restored) | unknown 8 `journal-truncated` |
| another record at the anchored sequence | unknown 8 `journal-anchor-mismatch` |
| more than one record past the anchor (an older anchor restored) | unknown 8 `journal-anchor-stale` |
| journal file removed while the anchor exists | unknown 8 `journal-missing-anchored` |
| anchor missing, unreadable, malformed, or naming another journal or authority | unknown 8 `journal-anchor-missing`, `-unreadable`, `-invalid`, `-foreign` |

`create` refuses while the anchor file exists (`journal-anchor-exists`), so a
removed journal cannot be created again with its old request IDs. A failed
anchor write is unknown 8 `journal-anchor-write-failed`; the record before it is
durable and the next transaction catches the anchor up. Limits: a person who can
remove both files, or restore both to the same older state, is not detected; a
journal opened without `anchor_path` keeps the M7 behavior, in which the removal
of whole trailing records and a recreated journal are not detected.

### Claims, dispatch and receipts

- `acquire` registers a request binding and either acquires its scope (fence + 1,
  60-second lease, heartbeat interval of at most 20 seconds) or coalesces into
  the scope's active leased claim. A request ID is registered once.
- `heartbeat` renews a live lease by 60 seconds. A lease is expired at or after
  leaseUntil on the supplied clock and is first recorded as orphaned, so a later
  or reset clock cannot revive it.
- The request window [createdAt, expiresAt) is checked at acquisition,
  heartbeat, dispatch and retry. A binding valid for more than 24 hours is
  invalid input (3); exactly 24 hours is allowed.
- `dispatch` is the execution-side dispatch boundary and the only function that
  calls a sender. It reconstructs and binds the six dispatch inputs with the M6
  helper (invalid shapes 3, stale fixed bytes 5), then under the lock requires
  the binding to equal the journaled request record, including trust,
  authorityId and authorityKind; authorityKind local-single-supervisor-v1; and
  an acquired (not coalesced), leased and unexpired claim of this authority. It
  syncs a submit-unknown record and then calls the sender once. A second
  dispatch never sends again (unknown, 8). A lost response is unknown (8).
- `reconcile` asks the query for runs of the submitted request and adopts the
  single run matching request ID, plan hash and workflow commit. Zero matches is
  unknown (8): this version has no definitive non-acceptance source. More than
  one is blocked (4). A query that raises any exception is unknown (8,
  `reconcile-observation-failed`) and records nothing; malformed candidates stay
  invalid input (3).
- `adopt` fixes attempt number, run ID, provider attempt and fence once
  (compare-and-set); another value is blocked. A retried attempt records the
  previous attempt's terminal receipt digest.
- `start_local` (M8) starts the local attempt of an acquired claim whose binding
  targets local: the submit-unknown record and an adoption with adoptedRunId and
  adoptedProviderAttempt null are appended in one transaction, before any check
  process starts. A started attempt is never started again (unknown, 8).
- `ingest_receipt` keeps one receipt per (requestId, attemptNumber, fence),
  checked against the journaled binding and adoption. The same domain hash is a
  no-op; a different one is recorded as a conflict and blocks (4) for that key,
  while the first receipt stays the record.
- `close` requires the attempt's terminal receipt, confirmed cleanup and no
  conflict. `retry` requires an orphaned claim, the current attempt's terminal
  receipt and cleanup, and an explicit approval recorded after the orphaning.
  An attempt whose receipt has status unknown is not terminal for retry: retry is
  blocked (4, `attempt-terminal-unknown`) and no second send is authorized.
  `close` still releases the claim without a send, so the owner can issue a new
  request (a new request ID) instead.

Acquisition, coalescing, heartbeat, submission and adoption are non-terminal
observations with `exitCode` null. They create no execution document and no
accepted result. `observe_completion` gives a terminal verdict: shape errors (3)
first, then the request's acquired claim, an adoption equal in every field to the
execution's attemptAuthority, the acquired claim's hash, no unresolved conflict
and the recorded receipt of that attempt, and finally the M5/M6 verifier with the
journaled binding. Acceptance (0) needs a collector ledger: the synthetic one in
tests, or the local supervisor ledger of M8.

Not implemented: github-run-v1 authority, a GitHub collector, a provider
connection, a CLI for the individual claim operations, and owner resolution of a
receipt conflict. Tests use temporary folders, a replaced clock, synthetic probes
for operating system queries, and two to four child processes for the
concurrency case r17.

## M8: execute on this computer

```sh
PYTHONPATH=src python -m ci_contract execute --plan plan.json --target local --out receipt \
  --repo-path <git repository> [--snapshot <directory>] --host local-host.json \
  --journal <journal file> --anchor <anchor file> --authority-id <id> [--new-journal] [--request-id <id>]
```

`execute` runs the plan's checks here and prints the final verdict's status
(stdout) and, when it is not 0, the status and its fixed reason code (stderr).
Exit codes are those of `verify`. `--target github` is blocked (4,
`execute-target-unsupported`): dispatch, read-only observation and evidence
retrieval of a provider run are a later stage. The journal and its anchor are
required; `--new-journal` creates them (at step 4, so a refusal of an earlier
step creates nothing) and refuses an existing anchor. Every outcome prints its
status, an operating-system error before the attempt starts included (error 9,
`local-io-failed`, e.g. a declared path longer than Windows allows). The
request ID defaults to `local-` and the plan hash, so running the same plan again
stops at the claim (4, `request-id-exists`); a new request is a new
`--request-id`.

The order is fixed, and nothing of a later step happens when an earlier one
refuses:

1. Shapes (3); then, without any Git read or process: `--target github`, the
   operations profile (`blocked-contract`, spec section 2), a release plan
   without a commit source, `localAllowed` false, and for every check its
   variant's os and arch against this computer, its required capabilities
   against the host description, network `none`, a shard total of 1, and a
   registered adapter and dataset. One check this host cannot run blocks the
   whole plan (`capability-unavailable`, c09): no check is dropped or replaced.
2. The M6 preflight with the quality projection read from the base commit; then
   the plan is rebuilt from the repository (a commit plan from its embedded
   selection request, a snapshot plan from its directory with the same explicit
   includes). A changed source is stale (5, `source-changed`, c12); any other
   difference is a plan the planner did not produce (4,
   `plan-reconstruction-mismatch`).
3. The declared inputs are written to a new private folder in the system
   temporary directory (snapshot M8 C2) and must reproduce the plan's digest.
   Each check's adapter entry and dataset are declared inputs whose bytes must
   match the plan's `adapterSha256` and the variant's dataset digest.
4. The receipt folder is created (it must not exist), the journal opened (with
   `--new-journal`, created), the request acquired and the local attempt
   started (`claim.start_local`).
5. The checks run one at a time in dependency order (by instance ID within a
   layer, so the order does not depend on the order of the plan file):
   `python -I -B <adapter entry> <argv...>` with the private folder as its tree
   and the check's `cwd` and time limit. The claim is renewed before each check
   starts, every 10 seconds while one runs or while the supervisor measures the
   tree or copies payloads, and once more right before the receipt is recorded;
   a claim that cannot be renewed (expired or orphaned lease) ends the execution
   (unknown 8). After each check the declared inputs are measured again: a check
   that changed one, its adapter entry or dataset included, ends the execution
   before the next check starts (stale 5). A check that depends on a generation
   check starts only while the generated payload files are still the bytes its
   proof will name; a check that overwrote one ends the execution (unknown 8,
   `generated-input-changed`). Other files the checks write are shared by all
   checks of the execution and are not evidence.
6. The execution, result and local supervisor ledger are verified (M5 with the
   journaled binding), recorded as the attempt's receipt and closed, then
   written. Every outcome after `start_local` is recorded, an operating-system
   error, memory exhaustion and a clock that fails included (unknown 8). If the
   verifier refuses the supervisor's own documents, an unknown receipt without
   checks or artifacts is recorded and closed and the verdict is error 9
   (`supervisor-documents-invalid`, `supervisor-verdict-unstable`); a receipt
   folder that cannot be written is error 9 (`receipt-folder-unwritable`) after
   the receipt is recorded.

### Trusted host description

```json
{"kind":"ci-contract-local-host-v1",
 "adapters":[{"id":"<adapter id>","runner":"python","entry":"<repository path>"}],
 "datasets":[{"id":"<dataset id>","path":"<repository path>"}],
 "capabilities":[{"id":"<capability id>","value":"<value>"}]}
```

The owner of this computer supplies it. Adapter entries and datasets name files
of the repository, so their bytes are fixed by the plan's source digest; only the
runner `python` exists in v1. The platform (`os`, `arch`) is observed, never
declared. The execution's capabilities are the declared ones plus `os` and
`arch`.

### Adapter protocol

The child's whole environment is `CI_CONTRACT_REPORT` (a file path outside the
tree), a private home and temporary folder (`HOME`/`TMPDIR` or
`USERPROFILE`/`TEMP`/`TMP`), `PATH` (`/usr/bin:/bin`, or the Windows system
folders) and, on Windows, `SYSTEMROOT`. No `GIT_*` variable and nothing else of
the caller's environment is passed. (On POSIX the Python interpreter of the
check adds `LC_CTYPE` itself when it coerces the C locale, PEP 538.) Before it exits the adapter writes one JSON
object to `CI_CONTRACT_REPORT`: kind `ci-contract-adapter-report-v1` and the
collection fields of an embedded proof (expected, executed, passed and failed
case IDs, skipped cases, `collectionComplete`, `targetPaths`,
`analysisCompleted`, `diagnosticCount`) and `payloads`
(`[{"artifactId", "path"}]`, files the check wrote in its tree, at most 256 MiB
each, 2 GiB and 10000 artifacts per execution; the result lists at most 10000).
Each payload is copied to `artifacts/` in chunks when the report is read. An
artifact ID is the file name in `artifacts/`: it must be a valid
inventory path segment (no reserved device name, no trailing dot or space) and
unique in the execution. The supervisor
supplies everything else of the proof from its own observations: the runtime
(os, arch, the Python interpreter's digest, the dataset digest it measured, the
host fingerprint), the invocation (adapter entry, argv, cwd, times and exit
code), the payload digests and sizes, the plan's enumeration contract, the
collector identity and the event log digest.

| What the supervisor observes | Result |
|---|---|
| every check ran, exited 0 and its report satisfies the proof policy | accepted 0 |
| a check exited non-zero with a usable report (every check still runs) | failed 2 |
| a test that executed no case, a skipped or incomplete collection | blocked 4 (the check is `skipped` or the verifier refuses it) |
| a declared input in the tree changed, replaced by a directory or a link, or hardlinked by a check | stale 5 (later checks do not start) |
| a check over its `timeoutSeconds`: its process tree is stopped, later checks do not start | timeout 7 (`check-timeout`) |
| no report, an unreadable or malformed report, a report that makes no valid proof (an artifact ID that is no valid file name or is used twice, a payload over a limit), a signal, a lost claim, a generated payload changed before its dependent starts, an operating-system error, memory exhaustion, a clock that fails | unknown 8 |
| a process tree whose end cannot be confirmed within 5 seconds | unknown 8 (cleanup unconfirmed; the claim is not closed) |

Every process of a check is in one Windows job object (the child is created
suspended and assigned before it runs) or one new POSIX session. After the check
ends, any process still in it is stopped and the end of all of them is
confirmed; a descendant left running does not survive its check.

### Receipt folder

`plan.json` and `execution.json` (written when the attempt starts),
`result.json`, `ledger.json` (the local supervisor ledger) and `events.json`
(the supervisor's events per check; each proof binds its digest) written after
the receipt is recorded, `logs/` (the adapter's console output, not evidence)
and `artifacts/` (payload bytes, exactly the result's artifacts: a report that
makes no receipt leaves none of its files). The
private tree, the reports and the private homes are removed at the end,
read-only files and names with a trailing dot included. Each check gets a new
report folder and private home, named when it starts, so an earlier check
cannot write a later check's report.

The local supervisor ledger (`local-supervisor-ledger-v1`, collector
`local-supervisor`) is accepted by `verify` only for a local execution and has
no GitHub observation. Like the synthetic ledger it is evidence from its
producer: `verify` with the three files alone stays blocked (4), and reading a
ledger back from a receipt folder is not an independent observation (collector
authentication is a later acceptance, spec section 6).

### Decisions not fixed by the specification

- D1 the supervisor is the collector; D2 adapters come from the trusted host
  description and are pinned by `adapterSha256`; D3 the report file protocol
  above; D4 the minimal environment; D5 time limits and confirmed cleanup; D6 a
  network other than `none` is a missing capability; D7 private copies of the
  declared inputs; D8 the journal and anchor are required and nothing is resumed
  from the journal after a crash (the attempt stays unknown).
- The execution deadline is its start plus each check's limit and 5 seconds per
  check, 0.02 seconds per declared file and check (the supervisor measures every
  declared file after each check; 5 ms per file were measured on Windows), plus
  30 seconds. Passing it ends the execution (`deadline-exceeded`, timeout 7);
  copying and re-measuring payloads counts in the 30 seconds.
- `engineSha256` is the plan's pinned bundle (as for every result of this
  engine); the running engine is measured as the collector's binary digest.
- On POSIX, a supervisor that is PID 1 or a subreaper reaps the stopped
  descendants it inherits, so they do not stay as zombies in the group.
- Limits: the network declaration is not enforced and a check can read or
  write files outside its tree (no sandbox in v1); the checks run with the
  owner's permissions and are the repository's own adapters pinned by digest:
  the supervisor prevents accidents (environment, stray processes, changed
  inputs, a later check's report), not a check written to attack it; a POSIX
  descendant that starts its own session or moves to another process group
  (`setpgid`) escapes, and the group is found by the leader's process ID (a
  reused ID after the group ended is not detected); the adapter protocol
  carries no shard, so a shard of a larger partition is refused.

## Existing checkout line endings

Text files are normalized to LF in the index and on checkout, including when
core.autocrlf=true. A clone checked out before these attributes were added may
retain earlier line endings until checkout is refreshed. Preserve local edits
separately before using a fresh checkout, or review normalization changes from
git add --renormalize . before committing. Do not discard local edits merely to
refresh line endings.
