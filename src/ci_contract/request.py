"""Typed selection and preflight over separately supplied, fixed trusted inputs.

No process, provider, filesystem, clock or authority state is consulted here.
The Git CLI adapter explicitly materializes fixed objects via gitsource only.
"""
import copy
from importlib.resources import files
from . import cjson
from .arrays import normalize
from .errors import InputError, BlockedError
from .hashing import raw_hash, canonical_hash, domain_hash
from .inventory import validate_path, normalize_inventory, source_digest
from .schema import load_schema, make_validator, validate
from .plan import (_compile, _broaden_manifest, _quality, _quality_not_reduced,
                   _unknown_path_fallback, MANIFEST, POLICY, PROJECTION, ENGINE_LOCK)
from .selection import select

PIN_PATHS = {'manifest': MANIFEST, 'policy': POLICY,
             'qualityProjection': PROJECTION, 'engineLock': ENGINE_LOCK}
PROFILES = ('change', 'case', 'integration', 'release', 'operations')


class StaleError(BlockedError):
    """Fixed bytes or a reconstructed plan differ from the requested identity."""


def _shape(value, definition):
    schema = load_schema()
    schema = {'$schema': schema['$schema'], '$defs': schema['$defs'],
              '$ref': '#/$defs/' + definition}
    cjson.dumps(value)
    if next(make_validator(schema).iter_errors(value), None) is not None:
        raise InputError('invalid request structure')


def read_selection(value):
    """Decode without trimming, validate closed shape and exact array classes."""
    value = cjson.loads(value) if type(value) is bytes else copy.deepcopy(value)
    _shape(value, 'selectionRequest')
    value = normalize(value, 'selection-request')
    if len(cjson.dumps(value)) > 16384:
        raise InputError('selection request too large')
    for pin in value['expectedPins'].values():
        validate_path(pin['path'])
    return value


def _profile(profile):
    if type(profile) is not str or profile not in PROFILES:
        raise InputError('invalid request profile')


def _controls(trusted_inputs):
    """Validate every available document before checking any missing/stale pin."""
    if type(trusted_inputs) is not dict or set(trusted_inputs) - set(PIN_PATHS):
        raise InputError('invalid trusted input registry')
    documents = {}
    for name, item in trusted_inputs.items():
        if type(item) is not dict or set(item) != {'ref', 'bytes'} or type(item['bytes']) is not bytes:
            raise InputError('invalid trusted input')
        _shape(item['ref'], 'trustedRef')
        validate_path(item['ref']['path'])
        value = cjson.loads(item['bytes'])
        if name == 'policy':
            if (type(value) is not dict or set(value) != {'kind','version','repositoryId','profiles','repoFullProfileApproved'}
                    or value['kind'] != 'synthetic-plan-policy' or type(value['version']) is not int
                    or value['version'] != 1 or type(value['repositoryId']) is not str
                    or value['profiles'] != ['change'] or value['repoFullProfileApproved'] is not False):
                raise InputError('unsupported policy structure')
        else:
            validate(value)
            expected = {'manifest':'manifest', 'qualityProjection':'quality-projection','engineLock':'engine-lock'}[name]
            if value['kind'] != expected:
                raise InputError('wrong trusted input kind')
            normalize(value)
        documents[name] = value
    return documents


def match_pins(selection, trusted_inputs):
    selection = read_selection(selection)
    documents = _controls(trusted_inputs)
    for name, expected in selection['expectedPins'].items():
        actual = trusted_inputs.get(name)
        if actual is None or any(actual['ref'][key] != expected[key] for key in ('repositoryId','commit','path')):
            raise BlockedError('fixed-reference-unavailable')
        if (raw_hash(actual['bytes']) != expected['sha256']
                or actual['ref']['sha256'] != expected['sha256']):
            raise StaleError('fixed-reference-stale')
    return documents


def build_selection_plan(selection, profile, *, trusted_inputs, source, base_source,
                         target_manifest, target_projection, changes, repository_group=None):
    """Rebuild from fixed controls and inventories supplied by a trusted caller.

    The caller supplies controls independently of the request. A requested pin
    never becomes a retrieval URL or replaces these controls. Target metadata
    can broaden selection, not replace policy or engine bytes.
    """
    selection = read_selection(selection)
    _profile(profile)
    if repository_group is not None and repository_group not in ('public','private','github-only','excluded'):
        raise InputError('invalid trusted repository group')
    _shape(source, 'source')
    _shape(base_source, 'source')
    normalize_inventory(source['inputs'])
    normalize_inventory(base_source['inputs'])
    validate(target_manifest)
    validate(target_projection)
    if target_manifest['kind'] != 'manifest' or target_projection['kind'] != 'quality-projection':
        raise InputError('wrong target control kind')
    normalize(target_manifest)
    normalize(target_projection)
    # Validate changes independently, even when an explicit/full mode ignores impact.
    if type(changes) is not list:
        raise InputError('invalid changes')
    for change in changes:
        if (type(change) is not dict or set(change) != {'status','path'}
                or change['status'] not in ('add','modify','delete')):
            raise InputError('invalid change')
        validate_path(change['path'])
    if len({c['path'] for c in changes}) != len(changes):
        raise InputError('duplicate change')
    docs = _controls(trusted_inputs)
    if set(docs) != set(PIN_PATHS):
        match_pins(selection, trusted_inputs)
    manifest, projection, lock = (docs[k] for k in ('manifest','qualityProjection','engineLock'))
    repository = manifest['repository']
    # Compilation validates references and paths before unsupported profile/group decisions.
    compile_profile = profile if profile in ('change','case') else 'change'
    compact, expanded, base_roles, base_nodes = _compile(manifest, compile_profile)
    broadened, deferred = _broaden_manifest(manifest, target_manifest)
    target_compact, _, target_roles, nodes = _compile(broadened, compile_profile)
    if profile == 'case':
        for model, checks in ((compact, expanded), (target_compact, expanded)):
            model['guardInstanceIds'] = sorted(set(model['guardInstanceIds']) |
                                               {iid for iid,c in checks.items() if c['always']})
    requested_instances = []
    # An explicit case asks the declared native check to run, conservatively
    # retaining its complete expected case set and immutable argv.
    requested = list(selection['requestedCheckIds']) + [case['checkId'] for case in selection['cases']]
    for identifier in requested:
        resolved = [iid for iid,c in expanded.items() if identifier in (iid,c['logicalCheckId'])]
        if not resolved:
            raise InputError('undeclared requested check')
        requested_instances.extend(resolved)
    for case in selection['cases']:
        resolved = [c for iid,c in expanded.items() if case['checkId'] in (iid,c['logicalCheckId'])]
        if any(c['kind'] != 'test' or not set(case['caseIds']) <= set(c['proofPolicy']['expectedCaseIds']) for c in resolved):
            raise InputError('undeclared requested case')
    match_pins(selection, trusted_inputs)
    if (source['baseCommit'] != selection['baseCommit'] or source['comparison'] != selection['comparison']
            or repository['id'] != selection['repositoryId']
            or target_manifest['repository']['id'] != repository['id']
            or docs['policy']['repositoryId'] != repository['id']):
        raise BlockedError('request-source-mismatch')
    if repository_group == 'excluded':
        raise BlockedError('excluded-scope')
    if (lock['engine'] != manifest['engine']
            or lock['engine']['schemaSha256'] != raw_hash(files('ci_contract').joinpath('data/contract-v1.schema.json').read_bytes())):
        raise StaleError('engine-pin-mismatch')
    if (manifest['policySha256'] != selection['expectedPins']['policy']['sha256']
            or manifest['qualityProjectionRef'] != selection['expectedPins']['qualityProjection']
            or cjson.dumps(normalize(projection)) != trusted_inputs['qualityProjection']['bytes']):
        raise StaleError('control-pin-mismatch')
    _quality(manifest, projection)
    _quality_not_reduced(projection, target_projection)
    if (source_digest(normalize_inventory(source['inputs'])) != source['digest']
            or source_digest(normalize_inventory(base_source['inputs'])) != base_source['digest']):
        raise StaleError('source-inventory-mismatch')
    mode = selection['mode']
    if mode == 'full':
        broad_instances = sorted(expanded)
        fallback = {'scope':'repo-broad','componentIds':[], 'reasons':['explicit-repo-full-request']}
        target_compact = compact
        selected_changes = []
    elif mode == 'explicit':
        broad_instances, fallback, selected_changes = [], {'scope':'none','componentIds':[], 'reasons':[]}, []
    else:
        broad_instances, fallback = _unknown_path_fallback(
            manifest, compact, target_compact, nodes, expanded, changes, profile)
        selected_changes = changes
    broad_instances.extend(requested_instances)
    if (any(entry['kind'] == 'file' and entry['path'] not in target_roles for entry in source['inputs'])
            or any(entry['kind'] == 'file' and entry['path'] not in base_roles for entry in base_source['inputs'])):
        raise BlockedError('undeclared-source-input')
    # The M2 profile gate is supplied only an explicitly declared instance set.
    if profile == 'case':
        compact = copy.deepcopy(compact)
        target_compact = copy.deepcopy(target_compact)
        compact['profileInstanceIds'] = {'case': sorted(set(broad_instances))}
        target_compact['profileInstanceIds'] = {'case': sorted(set(broad_instances))}
    group = 'github-only' if repository['product'] == 'github-only' else repository['group']
    if repository_group is not None and repository_group != group:
        raise BlockedError('trusted-scope-mismatch')
    selected = select({'model':target_compact,'baseModel':compact,'changes':selected_changes,
                       'scope':{'repositoryGroup':group},'profile':profile,
                       'requiredInstanceIds':sorted(set(broad_instances))})
    if selected['exitCode'] == 3:
        raise InputError('invalid selection model')
    if selected['exitCode'] != 0:
        raise BlockedError(selected['reasonCode'])
    ids = selected['selectedInstanceIds']
    checks = [expanded[i] for i in ids]
    reached = set(selected['evidence']['reachedComponents'])
    schema_changes = [{'status':{'add':'added','modify':'modified','delete':'deleted'}[c['status']],
                       'oldPath':None if c['status']=='add' else c['path'],
                       'newPath':None if c['status']=='delete' else c['path']} for c in changes]
    plan = {'kind':'plan','contractVersion':'1.0','repository':copy.deepcopy(repository),
            'engine':copy.deepcopy(lock['engine']),'manifestSha256':selection['expectedPins']['manifest']['sha256'],
            'policySha256':selection['expectedPins']['policy']['sha256'],'source':copy.deepcopy(source),'profile':profile,
            'requirements':sorted({r for c in checks for r in c['requirementIds']}),'checks':checks,
            'removedObligations':[],'exceptions':[],
            'selectionReasons':['base-target-graph-union-with-trusted-base-checks','changed-source-and-required-guards'] if mode=='changed' else ['explicit-'+mode+'-request','declared-native-checks-and-required-guards'],
            'omissionReasons':['not-reached-or-required:'+i for i in selected['notSelectedInstanceIds']] + deferred,
            'selectionRequest':selection,'selectionRequestSha256':canonical_hash(selection,'selection-request'),
            'qualityProjectionRef':copy.deepcopy(manifest['qualityProjectionRef']),
            'qualityProjectionSha256':canonical_hash(projection),
            'selectionEvidence':{'graphVersion':'literal-impact-v1','baseModelSha256':canonical_hash(normalize(manifest)['selectionModel']),
                                  'targetModelSha256':canonical_hash(normalize(target_manifest)['selectionModel']),
                                  'baseInventorySha256':base_source['digest'],'targetInventorySha256':source['digest'],
                                  'changes':schema_changes,'impactedComponentIds':sorted({cid for (cid,_),node in nodes.items() if node in reached}),
                                  'selectedInstanceIds':ids,'fallback':fallback,'completenessVerified':False}}
    plan = normalize(plan)
    validate(plan)
    return plan


def preflight(plan, target, *, quality_projection):
    """A pure pre-execution verdict; this never constructs an execution document."""
    try:
        validate(plan)
        if plan['kind'] != 'plan':
            raise InputError('wrong plan kind')
        normalize(plan, 'plan')
        if target not in ('local','github'):
            raise InputError('invalid execution target')
        if quality_projection is not None:
            validate(quality_projection)
            if quality_projection['kind'] != 'quality-projection':
                raise InputError('wrong projection kind')
            normalize(quality_projection)
        if plan['source']['mode'] == 'snapshot' and target == 'github':
            return {'status':'blocked','exitCode':4}
        if target == 'local' and (not plan['repository']['localAllowed']):
            return {'status':'blocked','exitCode':4}
        if quality_projection is None:
            return {'status':'blocked','exitCode':4}
        if (quality_projection['repositoryId'] != plan['repository']['id']
                or canonical_hash(quality_projection) != plan['qualityProjectionSha256']):
            return {'status':'stale','exitCode':5}
        return {'status':'ready','exitCode':0}
    except InputError:
        return {'status':'invalid-input','exitCode':3}


def dispatch_inputs(plan, request_id, workflow_commit):
    validate(plan)
    if plan['kind'] != 'plan':
        raise InputError('wrong plan kind')
    normalize(plan, 'plan')
    _shape(request_id, 'id')
    _shape(workflow_commit, 'git')
    if plan['source']['mode'] != 'commit':
        raise BlockedError('snapshot-dispatch-unsupported')
    selection = read_selection(plan['selectionRequest'])
    if canonical_hash(selection,'selection-request') != plan['selectionRequestSha256']:
        raise BlockedError('selection-binding-mismatch')
    return {'plan_sha256':domain_hash('plan',plan),'target_sha':plan['source']['targetCommit'],
            'profile':plan['profile'],'request_id':request_id,'expected_workflow_sha':workflow_commit,
            'selection_json':cjson.dumps(selection).decode('utf-8')}


def restore_dispatch(inputs):
    if type(inputs) is not dict or set(inputs) != {'plan_sha256','target_sha','profile','request_id','expected_workflow_sha','selection_json'}:
        raise InputError('invalid dispatch fields')
    for field, definition in (('plan_sha256','hash'),('target_sha','git'),('request_id','id'),('expected_workflow_sha','git')):
        _shape(inputs[field], definition)
    _profile(inputs['profile'])
    if type(inputs['selection_json']) is not str:
        raise InputError('invalid selection encoding')
    cjson.dumps(inputs['selection_json'])  # Reject non-scalar Unicode before UTF-8 encoding.
    selection = read_selection(inputs['selection_json'].encode('utf-8'))
    if inputs['selection_json'].encode('utf-8') != cjson.dumps(selection):
        raise InputError('noncanonical selection encoding')
    return selection


def reconstruct_dispatch(inputs, **fixed_inputs):
    selection = restore_dispatch(inputs)
    plan = build_selection_plan(selection, inputs['profile'], **fixed_inputs)
    if plan['source']['targetCommit'] != inputs['target_sha']:
        raise BlockedError('dispatch-target-mismatch')
    if domain_hash('plan', plan) != inputs['plan_sha256']:
        raise BlockedError('reconstructed-plan-mismatch')
    return plan


def reconstruct_bound_dispatch(inputs, binding, **fixed_inputs):
    """Reconstruct all six dispatch values against an independent request binding.

    The unbound reconstruction helper checks plan content only; execution callers
    use this boundary to bind the request identity and workflow revision too.
    """
    from .request_binding import validate_request_binding, plan_binding_fields
    restore_dispatch(inputs)
    validate_request_binding(binding)
    plan = reconstruct_dispatch(inputs, **fixed_inputs)
    if inputs['request_id'] != binding['requestId']:
        raise BlockedError('dispatch-request-mismatch')
    if inputs['expected_workflow_sha'] != binding['workflowCommit']:
        raise BlockedError('dispatch-workflow-mismatch')
    if inputs['plan_sha256'] != binding['planSha256']:
        raise BlockedError('dispatch-binding-plan-mismatch')
    if binding['target'] != 'github':
        raise BlockedError('dispatch-binding-target-mismatch')
    if any(binding[key] != value for key, value in plan_binding_fields(plan).items()):
        raise BlockedError('dispatch-binding-fields-mismatch')
    return plan


def fixed_inputs_from_git(repo_path, repository_id, base, target):
    """Materialize the existing M3 base trust boundary via its read-only adapter.

    No expectedPins field is used to choose trusted policy/engine documents.
    The separately selected base supplies those controls, as before M6.
    """
    from .gitsource import GitSource
    from .plan import _document, _policy
    git = GitSource(repo_path)
    git.verify_commit(base, 'base')
    git.verify_commit(target, 'target')
    manifest, manifest_bytes = _document(git, base, MANIFEST, 'manifest')
    if manifest['repository']['id'] != repository_id:
        raise InputError('repository mismatch')
    policy_bytes = _policy(git, base, repository_id, manifest['policySha256'])
    lock, lock_bytes = _document(git, base, ENGINE_LOCK, 'engine-lock')
    projection, projection_bytes = _document(git, base, PROJECTION, 'quality-projection')
    anchor = manifest['qualityProjectionRef']
    if anchor['repositoryId'] != repository_id or anchor['path'] != PROJECTION:
        raise InputError('projection reference mismatch')
    git.require_ancestor(anchor['commit'], base)
    anchored_bytes = git.read_blob(anchor['commit'], PROJECTION, side='projection-anchor')
    if anchored_bytes != projection_bytes:
        raise StaleError('projection-anchor-mismatch')
    target_manifest, _ = _document(git, target, MANIFEST, 'manifest', side='target')
    target_projection, _ = _document(git, target, PROJECTION, 'quality-projection', side='target')
    _, _, base_roles, _ = _compile(manifest, 'change')
    broadened, _ = _broaden_manifest(manifest, target_manifest)
    _, _, target_roles, _ = _compile(broadened, 'change')
    def item(path, data):
        return {'ref':{'repositoryId':repository_id,'commit':base,'path':path,'sha256':raw_hash(data)},'bytes':data}
    controls = {'manifest':item(MANIFEST,manifest_bytes),'policy':item(POLICY,policy_bytes),
                'engineLock':item(ENGINE_LOCK,lock_bytes),
                'qualityProjection':{'ref':copy.deepcopy(anchor),'bytes':projection_bytes}}
    source = git.source(base,target,{p:r for p,r in target_roles.items() if p in git.paths(target,side='target')})
    base_source = git.source(base,base,{p:r for p,r in base_roles.items() if p in git.paths(base,side='base')},side='base')
    return {'trusted_inputs':controls,'source':source,'base_source':base_source,
            'target_manifest':target_manifest,'target_projection':target_projection,'changes':git.changes(base,target)}


def build_request_from_git(repo_path, repository_id, selection, target, profile='change'):
    selection = read_selection(selection)
    _profile(profile)
    if selection['repositoryId'] != repository_id:
        raise InputError('repository mismatch')
    if selection['baseCommit'] is None:
        raise BlockedError('trusted-base-anchor-required')
    inputs = fixed_inputs_from_git(repo_path, repository_id, selection['baseCommit'], target)
    return build_selection_plan(selection, profile, **inputs)
