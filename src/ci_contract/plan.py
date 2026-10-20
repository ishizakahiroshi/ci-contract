"""M3 commit-only planning. No execution, provider, private-ledger or clock input.

Trusted controls are read from base. Target controls are source bytes, never a
replacement for the base selector. Unsupported policy dialects fail closed.
"""
import copy
from importlib.resources import files
from . import cjson
from .arrays import normalize
from .errors import InputError, BlockedError
from .hashing import raw_hash, canonical_hash, domain_hash
from .schema import validate
from .selection import select

MANIFEST = '.ci/manifest.json'
PROJECTION = '.ci/quality-projection.json'
POLICY = '.ci/policy.json'
ENGINE_LOCK = '.ci/engine.lock.json'


def variant_id(variant):
    return 'v-' + canonical_hash(_variant(variant))


def instance_id(logical_id, variant):
    return 'i-' + canonical_hash({'logicalCheckId': logical_id, 'variant': _variant(variant)})


def _variant(variant):
    # Reuse the exact registered plan path rather than infer a new array kind.
    return normalize({'kind': 'plan', 'checks': [{'id': 'synthetic', 'variant': variant}]})['checks'][0]['variant']


def _document(git, commit, path, kind, side='base'):
    try:
        data = git.read_blob(commit, path, side=side)
    except BlockedError:
        prefix = 'target-' if side == 'target' else ''
        raise BlockedError(prefix + kind + '-unavailable') from None
    value = cjson.loads(data)
    if type(value) is not dict or value.get('kind') != kind:
        raise InputError('unexpected control kind')
    validate(value)
    return value, data


def _unique(items, key='id'):
    result = {}
    for item in items:
        name = item[key]
        if name in result:
            raise InputError('duplicate control identifier')
        result[name] = item
    return result


def _policy(git, base, repository_id, digest):
    """Deliberately synthetic M3 policy, not an invented production contract."""
    try:
        data = git.read_blob(base, POLICY, side='base')
    except BlockedError:
        raise BlockedError('policy-unavailable') from None
    value = cjson.loads(data)
    if raw_hash(data) != digest:
        raise InputError('policy pin mismatch')
    if (type(value) is not dict or set(value) != {
            'kind', 'version', 'repositoryId', 'profiles', 'repoFullProfileApproved'}
            or value.get('kind') != 'synthetic-plan-policy'
            or type(value.get('version')) is not int or value['version'] != 1
            or value.get('repositoryId') != repository_id
            or value.get('profiles') != ['change']
            or value.get('repoFullProfileApproved') is not False):
        raise BlockedError('unsupported-policy')
    return data


def _quality(manifest, projection):
    """Reject unresolved or ambiguous quality mappings before selection."""
    if projection['repositoryId'] != manifest['repository']['id']:
        raise InputError('projection repository mismatch')
    requirements = _unique(manifest['requirements'])
    checks = _unique(manifest['checks'])
    projected = _unique(projection['requirements'])
    if normalize(manifest)['requirements'] != normalize(projection)['requirements']:
        raise BlockedError('quality-requirements-unmapped')
    mappings = {}
    for mapping in projection['mappings']:
        external = mapping['externalReference']
        if external in mappings:
            raise BlockedError('quality-mapping-ambiguous')
        mappings[external] = mapping
    external_ids = set()
    for requirement in requirements.values():
        if not set(requirement['checkIds']) <= checks.keys():
            raise BlockedError('quality-check-unmapped')
        if any(requirement['id'] not in checks[lid]['requirementIds'] for lid in requirement['checkIds']):
            raise BlockedError('quality-check-unmapped')
        for external in requirement['externalReferences']:
            if external in external_ids:
                raise BlockedError('quality-mapping-ambiguous')
            external_ids.add(external)
            mapping = mappings.get(external)
            if (mapping is None or mapping['requirementId'] != requirement['id']
                    or set(mapping['logicalCheckIds']) != set(requirement['checkIds'])):
                raise BlockedError('quality-mapping-unmapped')
    if set(mappings) != external_ids or projected.keys() != requirements.keys():
        raise BlockedError('quality-mapping-unmapped')
    for check in checks.values():
        if (not set(check['requirementIds']) <= requirements.keys()
                or any(check['id'] not in requirements[r]['checkIds'] for r in check['requirementIds'])):
            raise BlockedError('quality-check-unmapped')
    # Exception evaluation and expiry belong to a later stage; do not imply
    # an unimplemented exemption is usable in this synthetic planning slice.
    if manifest['exceptions'] or projection['exceptionIds'] or any(m['exceptionIds'] for m in mappings.values()):
        raise BlockedError('exceptions-unsupported')


def _quality_not_reduced(base, target):
    """Compare obligation-bearing fields, not descriptive wording or labels.

    Base remains the authority. Purpose, revision, approvalRef, coverage and
    classification do not determine obligations and have no invented ranking.
    Applicability is a singleton profile or its explicit superset, all.
    """
    if target['repositoryId'] != base['repositoryId']:
        raise BlockedError('quality-obligations-reduced')
    old_requirements = _unique(base['requirements'])
    new_requirements = _unique(target['requirements'])
    old_mappings = _unique(base['mappings'], 'externalReference')
    new_mappings = _unique(target['mappings'], 'externalReference')
    if any(not set(mapping['exceptionIds']) <= set(old_mappings.get(ref, {}).get('exceptionIds', []))
           for ref, mapping in new_mappings.items()):
        raise BlockedError('quality-obligations-reduced')
    for rid, old in old_requirements.items():
        new = new_requirements.get(rid)
        if (new is None or old['releaseRequired'] and not new['releaseRequired']
                or any(not set(old[field]) <= set(new[field])
                       for field in ('checkIds', 'externalReferences', 'origins'))):
            raise BlockedError('quality-obligations-reduced')
    for ref, old in old_mappings.items():
        new = new_mappings.get(ref)
        if (new is None or old['requirementId'] != new['requirementId']
                or not set(old['logicalCheckIds']) <= set(new['logicalCheckIds'])
                or new['applicability'] not in (old['applicability'], 'all')
                or not set(new['exceptionIds']) <= set(old['exceptionIds'])):
            raise BlockedError('quality-obligations-reduced')
    if not set(target['exceptionIds']) <= set(base['exceptionIds']):
        raise BlockedError('quality-obligations-reduced')
    # Added references must resolve too; do not accept malformed broadening as
    # evidence. New target obligations remain deferred, never replace base ones.
    external_ids = set()
    for requirement in new_requirements.values():
        for ref in requirement['externalReferences']:
            mapping = new_mappings.get(ref)
            if (ref in external_ids or mapping is None
                    or mapping['requirementId'] != requirement['id']
                    or set(mapping['logicalCheckIds']) != set(requirement['checkIds'])):
                raise BlockedError('quality-mapping-unmapped')
            external_ids.add(ref)
    if external_ids != new_mappings.keys():
        raise BlockedError('quality-mapping-unmapped')


def _broaden_manifest(base, target):
    """Project target reachability onto the trusted executable universe.

    Both graphs contribute ownership/impact edges; base paths, mappings, roles,
    checks and guards cannot be removed or replaced. Target-only checks/variants
    are recorded but cannot supply an executable definition or prerequisite.
    """
    merged = copy.deepcopy(base)
    graph = merged['selectionModel']
    incoming = target['selectionModel']
    known = _unique(base['checks'])
    variants = {variant_id(v) for check in known.values() for v in check['variants']}
    target_components = _unique(incoming['components'])
    _unique(incoming['inputRules'])
    _unique(incoming['impactEdges'])
    complete = incoming['completeness']
    if (complete['status'] != 'complete' or complete['unmappedPaths']
            or set(complete['scopeComponentIds']) != target_components.keys()):
        raise BlockedError('incomplete-selection-model')
    components = _unique(graph['components'])
    deferred = {'target-only-check:' + c['id'] for c in target['checks'] if c['id'] not in known}
    for check in target['checks']:
        base_variants = {variant_id(v) for v in known.get(check['id'], {}).get('variants', [])}
        deferred.update('target-only-variant:' + check['id'] + ':' + variant_id(v)
                        for v in check['variants'] if variant_id(v) not in base_variants)
    for component in target_components.values():
        cid = component['id']
        if cid not in components:
            components[cid] = {'id': cid, 'broadLogicalCheckIds': []}
            graph['components'].append(components[cid])
        components[cid]['broadLogicalCheckIds'] = sorted(
            set(components[cid]['broadLogicalCheckIds']) |
            (set(component['broadLogicalCheckIds']) & known.keys()))

    def condition(value):
        return {'profiles': copy.deepcopy(value['profiles']),
                'variantIds': sorted(set(value['variantIds']) & variants)}

    roles = {rule['path']: rule['role'] for rule in graph['inputRules']}
    for rule in incoming['inputRules']:
        if not set(rule['componentIds']) <= target_components.keys():
            raise InputError('unknown target rule component')
        item = copy.deepcopy(rule)
        item['id'] = 'target-rule-' + canonical_hash(rule)
        item['role'] = roles.setdefault(item['path'], item['role'])
        item['condition'] = condition(item['condition'])
        if item['condition']['variantIds']:
            graph['inputRules'].append(item)
    seen_edges = {canonical_hash({k: v for k, v in edge.items() if k != 'id'})
                  for edge in graph['impactEdges']}
    for edge in incoming['impactEdges']:
        if any(edge[key] not in target_components for key in ('producerComponentId', 'consumerComponentId')):
            raise InputError('unknown target impact component')
        item = copy.deepcopy(edge)
        item['id'] = 'target-edge-' + canonical_hash(edge)
        item['condition'] = condition(item['condition'])
        identity = canonical_hash({k: v for k, v in item.items() if k != 'id'})
        if item['condition']['variantIds'] and identity not in seen_edges:
            graph['impactEdges'].append(item)
            seen_edges.add(identity)
    seen_mappings = {canonical_hash(mapping) for mapping in graph['checkMappings']}
    for mapping in incoming['checkMappings']:
        if not set(mapping['componentIds']) <= target_components.keys():
            raise InputError('unknown target mapping component')
        item = copy.deepcopy(mapping)
        item['logicalCheckIds'] = sorted(set(item['logicalCheckIds']) & known.keys())
        item['condition'] = condition(item['condition'])
        identity = canonical_hash(item)
        if item['logicalCheckIds'] and item['condition']['variantIds'] and identity not in seen_mappings:
            graph['checkMappings'].append(item)
            seen_mappings.add(identity)
    graph['completeness']['scopeComponentIds'] = sorted(components)
    return merged, sorted(deferred)


def _compile(manifest, profile):
    """Compile typed variant-conditioned graph into the unchanged M2 adapter.

Virtual nodes represent (component, variant) and literal-path multi-ownership.
They never appear as declared component IDs in plan evidence. Preparation
conservatively includes every variant of each declared prerequisite.
"""
    from .inventory import validate_path
    graph = manifest['selectionModel']
    components = _unique(graph['components'])
    rules = _unique(graph['inputRules'])
    logical = _unique(manifest['checks'])
    _unique(graph['impactEdges'])
    expanded, variants, by_logical = {}, {}, {}
    for check in logical.values():
        for path in check['inputPaths'] + check['proofPolicy']['expectedTargetPaths']:
            validate_path(path)
        if check['cwd'] != '.':
            validate_path(check['cwd'])
        if not set(check['inputRuleIds']) <= rules.keys():
            raise InputError('unknown check input rule')
        if not set(check['dependsOn']) <= logical.keys():
            raise InputError('unknown prerequisite')
        by_logical[check['id']] = []
        seen = set()
        for variant in check['variants']:
            vid = variant_id(variant)
            if vid in seen or variant['shard']['index'] >= variant['shard']['total']:
                raise InputError('invalid or duplicate variant')
            seen.add(vid)
            variants[vid] = _variant(variant)
            iid = instance_id(check['id'], variant)
            instance = {k: copy.deepcopy(v) for k, v in check.items() if k != 'variants'}
            instance.update(id=iid, logicalCheckId=check['id'], variant=_variant(variant))
            expanded[iid] = instance
            by_logical[check['id']].append(iid)
    for component in components.values():
        if not set(component['broadLogicalCheckIds']) <= logical.keys():
            raise InputError('unknown broad check')

    def condition(value, vid):
        if not set(value['variantIds']) <= variants.keys():
            raise InputError('unknown condition variant')
        return profile in value['profiles'] and vid in value['variantIds']

    nodes = {(component, vid): 'n-' + canonical_hash([component, vid])
             for component in components for vid in variants}
    compact = {'components': list(nodes.values()), 'literalInputOwners': {},
               'componentInstances': {node: [] for node in nodes.values()},
               'guardInstanceIds': [], 'impactEdges': [], 'prepareEdges': []}
    roles = {}
    owners = {}
    for rule in rules.values():
        path = validate_path(rule['path'])
        if not set(rule['componentIds']) <= components.keys():
            raise InputError('unknown rule component')
        if path in roles and roles[path] != rule['role']:
            raise InputError('ambiguous input role')
        roles[path] = rule['role']
        owners.setdefault(path, set())
        for vid in variants:
            if condition(rule['condition'], vid):
                owners[path].update(nodes[c, vid] for c in rule['componentIds'])
    for path, targets in owners.items():
        if not targets:
            continue
        node = 'p-' + canonical_hash(path)
        compact['components'].append(node)
        compact['literalInputOwners'][path] = node
        compact['componentInstances'][node] = []
        compact['impactEdges'].extend([[node, target] for target in sorted(targets)])
    for edge in graph['impactEdges']:
        producer, consumer = edge['producerComponentId'], edge['consumerComponentId']
        if producer not in components or consumer not in components:
            raise InputError('unknown impact component')
        for vid in variants:
            if condition(edge['condition'], vid):
                pair = [nodes[producer, vid], nodes[consumer, vid]]
                if pair not in compact['impactEdges']:
                    compact['impactEdges'].append(pair)
    declared_instances = set()
    for mapping in graph['checkMappings']:
        if not set(mapping['componentIds']) <= components.keys() or not set(mapping['logicalCheckIds']) <= logical.keys():
            raise InputError('unknown check mapping')
        for cid in mapping['componentIds']:
            for lid in mapping['logicalCheckIds']:
                for iid in by_logical[lid]:
                    vid = variant_id(expanded[iid]['variant'])
                    if vid in mapping['condition']['variantIds']:
                        declared_instances.add(iid)
                    if condition(mapping['condition'], vid):
                        ids = compact['componentInstances'][nodes[cid, vid]]
                        if iid not in ids:
                            ids.append(iid)
    for iid, instance in expanded.items():
        dependencies = [dep for lid in instance['dependsOn'] for dep in by_logical[lid]]
        instance['dependsOn'] = dependencies
        compact['prepareEdges'].extend([[iid, dep] for dep in dependencies])
        scope = instance['alwaysScope']
        if instance['always'] != (scope is not None):
            raise InputError('inconsistent guard scope')
        if scope is not None:
            declared_instances.add(iid)
            if not set(scope['componentIds']) <= components.keys():
                raise InputError('unknown guard component')
            if profile in scope['profiles']:
                if scope['scope'] == 'repo':
                    if scope['componentIds']:
                        raise InputError('ambiguous repository guard')
                    compact['guardInstanceIds'].append(iid)
                else:
                    if not scope['componentIds']:
                        raise InputError('empty component guard')
                    vid = variant_id(instance['variant'])
                    for cid in scope['componentIds']:
                        ids = compact['componentInstances'][nodes[cid, vid]]
                        if iid not in ids:
                            ids.append(iid)
    universe = set(compact['guardInstanceIds']) | {i for ids in compact['componentInstances'].values() for i in ids}
    if declared_instances != expanded.keys():
        raise BlockedError('unmapped-check-variant')
    # Keep declared instances that are inactive in this profile in the M2
    # universe, without giving them a reachable owner or dropping their identity.
    # A declared preparation dependency may still require them conservatively.
    if expanded.keys() - universe:
        dormant = 'inactive-' + canonical_hash(sorted(expanded.keys() - universe))
        compact['components'].append(dormant)
        compact['componentInstances'][dormant] = sorted(expanded.keys() - universe)
    completeness = graph['completeness']
    if (completeness['status'] != 'complete' or completeness['unmappedPaths']
            or set(completeness['scopeComponentIds']) != components.keys()):
        raise BlockedError('incomplete-selection-model')
    return compact, expanded, roles, nodes


def _unknown_path_fallback(manifest, base_compact, target_compact, nodes, expanded, changes, profile):
    """Resolve each unknown literal path independently to trusted broad checks.

    A target-only mapping or an unrelated changed path is not ownership proof.
    This bounded policy has no approved repo-full profile; unresolved unknowns
    block rather than manufacture an approval or count global guards as coverage.
    """
    known = _unique(manifest['selectionModel']['components'])
    node_component = {node: cid for (cid, _), node in nodes.items()}
    adjacency = {}
    for start, end in base_compact['impactEdges'] + target_compact['impactEdges']:
        adjacency.setdefault(start, set()).add(end)
    active_base_instances = {iid for (cid, _), node in nodes.items() if cid in known
                             for iid in base_compact['componentInstances'].get(node, [])}
    required, fallback_components = set(), set()
    for change in changes:
        path = change['path']
        if path in base_compact['literalInputOwners']:
            continue
        owner = target_compact['literalInputOwners'].get(path)
        if owner is None:
            raise BlockedError('unknown-path-no-approved-fallback')
        reached = {owner}
        pending = [owner]
        for node in pending:
            for consumer in adjacency.get(node, ()):
                if consumer not in reached:
                    reached.add(consumer)
                    pending.append(consumer)
        trusted = {node_component[node] for node in reached
                   if node in node_component and node_component[node] in known}
        if not trusted:
            raise BlockedError('unknown-target-owner-no-approved-fallback')
        instances = set()
        for cid in trusted:
            for iid, check in expanded.items():
                if check['logicalCheckId'] not in known[cid]['broadLogicalCheckIds']:
                    continue
                scope = check['alwaysScope']
                if check['always']:
                    eligible = (scope['scope'] == 'component'
                                and cid in scope['componentIds']
                                and profile in scope['profiles'])
                else:
                    eligible = iid in active_base_instances
                if eligible:
                    instances.add(iid)
        if not instances:
            raise BlockedError('unknown-path-no-trusted-broad-checks')
        required.update(instances)
        fallback_components.update(trusted)
    return sorted(required), {
        'scope': 'component-broad' if fallback_components else 'none',
        'componentIds': sorted(fallback_components),
        'reasons': ['unknown-path-to-trusted-component'] if fallback_components else []}


def build_plan(repo_path, repository_id, base, target, profile='change'):
    """Return a validated canonical plan object or safe InputError/BlockedError."""
    from .gitsource import GitSource
    if profile != 'change':
        raise InputError('unsupported planning profile')
    git = GitSource(repo_path)
    git.verify_commit(base, 'base')
    git.verify_commit(target, 'target')
    manifest, manifest_bytes = _document(git, base, MANIFEST, 'manifest')
    if manifest['repository']['id'] != repository_id:
        raise InputError('repository mismatch')
    # Repository admission precedes path-level fallback and source selection.
    if manifest['repository']['group'] == 'standalone':
        raise BlockedError('unsupported-repository-group')
    group = ('github-only' if manifest['repository']['product'] == 'github-only'
             else manifest['repository']['group'])
    policy_bytes = _policy(git, base, repository_id, manifest['policySha256'])
    lock, lock_bytes = _document(git, base, ENGINE_LOCK, 'engine-lock')
    if lock['engine'] != manifest['engine']:
        raise InputError('engine lock mismatch')
    if lock['engine']['schemaSha256'] != raw_hash(files('ci_contract').joinpath('data/contract-v1.schema.json').read_bytes()):
        raise InputError('engine schema pin mismatch')
    projection, projection_bytes = _document(git, base, PROJECTION, 'quality-projection')
    reference = manifest['qualityProjectionRef']
    if reference['repositoryId'] != repository_id or reference['path'] != PROJECTION:
        raise InputError('projection reference mismatch')
    git.require_ancestor(reference['commit'], base)
    try:
        anchor_projection = git.read_blob(reference['commit'], PROJECTION, side='projection-anchor')
    except BlockedError:
        raise BlockedError('projection-anchor-projection-unavailable') from None
    if (raw_hash(projection_bytes) != reference['sha256']
            or anchor_projection != projection_bytes):
        raise InputError('projection pin mismatch')
    # The fixed specification requires canonical JSON metadata; hash the actual
    # blob for pins, then require canonical equality rather than conflate hashes.
    if cjson.dumps(normalize(projection)) != projection_bytes:
        raise InputError('noncanonical quality projection')
    _quality(manifest, projection)
    target_manifest = manifest
    if target != base:
        target_quality, _ = _document(git, target, PROJECTION, 'quality-projection', side='target')
        _quality_not_reduced(projection, target_quality)
        target_manifest, _ = _document(git, target, MANIFEST, 'manifest', side='target')
    compact, expanded, base_roles, base_nodes = _compile(manifest, profile)
    broadened, deferred = _broaden_manifest(manifest, target_manifest)
    target_compact, _, target_roles, nodes = _compile(broadened, profile)
    target_paths = git.paths(target, side='target')
    base_paths = git.paths(base, side='base')
    changes = git.changes(base, target)
    broad_instances, fallback = _unknown_path_fallback(
        manifest, compact, target_compact, nodes, expanded, changes, profile)
    source = git.source(base, target, {p: r for p, r in target_roles.items() if p in target_paths})
    base_source = git.source(base, base, {p: r for p, r in base_roles.items() if p in base_paths}, side='base')
    if (any(entry['kind'] == 'file' and entry['path'] not in target_roles for entry in source['inputs'])
            or any(entry['kind'] == 'file' and entry['path'] not in base_roles for entry in base_source['inputs'])):
        raise BlockedError('undeclared-source-input')
    selected = select({'model': target_compact, 'baseModel': compact, 'changes': changes,
                       'scope': {'repositoryGroup': group}, 'profile': profile,
                       'requiredInstanceIds': broad_instances})
    if selected['exitCode'] == 3:
        raise InputError('invalid selection model')
    if selected['exitCode'] != 0:
        raise BlockedError(selected['reasonCode'])
    ids = selected['selectedInstanceIds']
    checks = [expanded[i] for i in ids]
    required = sorted({r for check in checks for r in check['requirementIds']})

    def pin(path, data):
        return {'repositoryId': repository_id, 'commit': base, 'path': path, 'sha256': raw_hash(data)}

    request = {'version': '1', 'repositoryId': repository_id, 'baseCommit': base,
               'comparison': 'head', 'mode': 'changed', 'requestedCheckIds': [], 'cases': [],
               'expectedPins': {'manifest': pin(MANIFEST, manifest_bytes),
                                'policy': pin(POLICY, policy_bytes),
                                'qualityProjection': copy.deepcopy(reference),
                                'engineLock': pin(ENGINE_LOCK, lock_bytes)}}
    request = normalize(request, 'selection-request')
    if len(cjson.dumps(request)) > 16 * 1024:
        raise InputError('selection request too large')
    schema_changes = [{'status': {'add': 'added', 'modify': 'modified', 'delete': 'deleted'}[c['status']],
                       'oldPath': None if c['status'] == 'add' else c['path'],
                       'newPath': None if c['status'] == 'delete' else c['path']} for c in changes]
    reached = set(selected['evidence']['reachedComponents'])
    impacted = sorted({cid for (cid, _), node in nodes.items() if node in reached})
    graph_hash = canonical_hash(normalize(manifest)['selectionModel'])
    target_graph_hash = canonical_hash(normalize(target_manifest)['selectionModel'])
    plan = {'kind': 'plan', 'contractVersion': '1.0', 'repository': copy.deepcopy(manifest['repository']),
            'engine': copy.deepcopy(lock['engine']), 'manifestSha256': raw_hash(manifest_bytes),
            'policySha256': raw_hash(policy_bytes), 'source': source, 'profile': profile,
            'requirements': required, 'checks': checks, 'removedObligations': [], 'exceptions': [],
            'selectionReasons': ['base-target-graph-union-with-trusted-base-checks', 'changed-source-and-required-guards'],
            'omissionReasons': ['not-reached-or-required:' + i for i in selected['notSelectedInstanceIds']] + deferred,
            'selectionRequest': request, 'selectionRequestSha256': canonical_hash(request, 'selection-request'),
            'qualityProjectionRef': copy.deepcopy(reference), 'qualityProjectionSha256': canonical_hash(projection),
            'selectionEvidence': {'graphVersion': 'literal-impact-v1', 'baseModelSha256': graph_hash,
                                  'targetModelSha256': target_graph_hash,
                                  'baseInventorySha256': base_source['digest'],
                                  'targetInventorySha256': source['digest'], 'changes': schema_changes,
                                  'impactedComponentIds': impacted, 'selectedInstanceIds': ids,
                                  'fallback': fallback,
                                  'completenessVerified': False}}
    # Graph generator/review attestation verification is outside M3. This flag
    # stays false; structural/path/reference closure above is not attestation.
    plan = normalize(plan)
    plan['selectionRequestSha256'] = canonical_hash(plan['selectionRequest'], 'selection-request')
    validate(plan)
    return plan


def plan_bytes(plan):
    validate(plan)
    return cjson.dumps(normalize(plan))


def plan_digest(plan):
    validate(plan)
    return domain_hash('plan', plan)
