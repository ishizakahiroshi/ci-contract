"""Pure M2 selection adapter: declared data in, deterministic evidence out.

No repository discovery, operating-system paths, I/O, execution or plan builder.
Instance identifiers are already expanded variants; preparation edges are
[dependent, prerequisite], never producer/consumer impact edges.
"""
import unicodedata
from .errors import InputError


def _object(value, allowed, required=()):
    if not isinstance(value, dict) or set(value) - set(allowed) or set(required) - set(value):
        raise InputError('invalid selection object')
    return value


def _name(value):
    if not isinstance(value, str) or not value or any(ord(c) < 32 or 0xD800 <= ord(c) <= 0xDFFF for c in value):
        raise InputError('invalid selection identifier')
    return value


def _names(value):
    if not isinstance(value, list):
        raise InputError('invalid selection list')
    result = [_name(item) for item in value]
    if len(set(result)) != len(result):
        raise InputError('duplicate selection identifier')
    return result


def _path(value):
    _name(value)
    reserved = {'con', 'prn', 'aux', 'nul'} | {f'{prefix}{n}' for prefix in ('com', 'lpt') for n in '123456789¹²³'}
    if (value != unicodedata.normalize('NFC', value)
            or any(c in value for c in '\\:<>"|?*')
            or any(ord(c) < 32 or 127 <= ord(c) <= 159 for c in value)
            or any(part in ('', '.', '..') or part.endswith(('.', ' '))
                   or part.split('.')[0].casefold() in reserved
                   for part in value.split('/'))):
        raise InputError('noncanonical selection path')
    return value


def _edges(value):
    if not isinstance(value, list):
        raise InputError('invalid selection edges')
    result = []
    for pair in value:
        if not isinstance(pair, list) or len(pair) != 2:
            raise InputError('invalid selection edge')
        edge = (_name(pair[0]), _name(pair[1]))
        if edge in result:
            raise InputError('duplicate selection edge')
        result.append(edge)
    return result


def _extend(result, values):
    for value in values:
        if value not in result:
            result.append(value)


def _closure(seeds, edges):
    reached = list(seeds)
    for node in reached:
        _extend(reached, (end for start, end in edges if start == node))
    return reached


def _cycle(edges):
    # Kahn's algorithm avoids recursion limits on long preparation chains.
    nodes = {n for edge in edges for n in edge}
    incoming = {n: 0 for n in nodes}
    adjacency = {n: [] for n in nodes}
    for start, end in edges:
        adjacency[start].append(end)
        incoming[end] += 1
    ready = sorted(n for n in nodes if not incoming[n])
    for node in ready:
        for end in adjacency[node]:
            incoming[end] -= 1
            if not incoming[end]:
                ready.append(end)
    return len(ready) != len(nodes)


def _model(value):
    keys = ('components', 'literalInputOwners', 'componentInstances',
            'guardInstanceIds', 'impactEdges', 'prepareEdges',
            'profileInstanceIds', 'pathInstanceIds')
    _object(value, keys, keys[:4])
    components = _names(value['components'])
    owners = value['literalInputOwners']
    mapping = value['componentInstances']
    if not isinstance(owners, dict) or not isinstance(mapping, dict):
        raise InputError('invalid selection mapping')
    for path, owner in owners.items():
        _path(path)
        if _name(owner) not in components:
            raise InputError('unknown component')
    for component, instances in mapping.items():
        if component not in components:
            raise InputError('unknown component')
        _names(instances)
    guards = _names(value['guardInstanceIds'])
    impact = _edges(value.get('impactEdges', []))
    if any(n not in components for edge in impact for n in edge):
        raise InputError('unknown impact component')
    prepare = _edges(value.get('prepareEdges', []))
    profiles = value.get('profileInstanceIds', {})
    rules = value.get('pathInstanceIds', {})
    if not isinstance(profiles, dict) or not isinstance(rules, dict):
        raise InputError('invalid selection mapping')
    for profile, instances in profiles.items():
        _name(profile)
        _names(instances)
    for path, instances in rules.items():
        _path(path)
        _names(instances)
    universe = list(guards)
    for component in components:
        _extend(universe, mapping.get(component, []))
    for instances in rules.values():
        _extend(universe, instances)
    # Profile entries reference the declared universe; they cannot invent checks.
    if any(i not in universe for ids in profiles.values() for i in ids):
        raise InputError('unknown profile instance')
    return dict(components=components, owners=owners, mapping=mapping,
                guards=guards, impact=impact, prepare=prepare,
                profiles=profiles, rules=rules, universe=universe)


def _result(status, code, reason, selected=(), omitted=(), reached=(), paths=(), fallback='none'):
    return {'status': status, 'exitCode': code, 'reasonCode': reason,
            'selectedInstanceIds': list(selected), 'notSelectedInstanceIds': list(omitted),
            'notSelectedReasons': [{'instanceId': i, 'reasonCode': 'not-reached-or-required'} for i in omitted],
            'evidence': {'reachedComponents': list(reached), 'changedPaths': list(paths),
                         'fallback': fallback}}


def select(value):
    """Select expanded instances without mutating input; invalid input is exit 3.

    Rejected plans have no partial selected/excluded partition. Every successful
    plan partitions the declared base/target universe and contains at least one
    instance. Model-independent root values and scope shapes are validated before
    scope rejection. Model shape validation follows scope admission, so excluded
    scope remains blocked even if its unused model is malformed. This is not a schema-v1 plan or CI result.
    """
    try:
        return _select(value)
    except InputError:
        return _result('invalid-input', 3, 'invalid-selection-input')


def _select(value):
    _object(value, ('model', 'baseModel', 'changedPaths', 'changes', 'scope',
                    'baseAvailable', 'repoFullProfileApproved', 'profile',
                    'requiredInstanceIds'), ('model', 'scope'))
    scope = _object(value['scope'], ('repositoryGroup', 'requestedAlias', 'aliases'), ('repositoryGroup',))
    group = _name(scope['repositoryGroup'])
    aliases = scope.get('aliases', {})
    if not isinstance(aliases, dict):
        raise InputError('invalid scope registry')
    for alias, canonical in aliases.items():
        _name(alias)
        _name(canonical)
    requested = scope.get('requestedAlias')
    if requested is not None:
        _name(requested)
    for field in ('baseAvailable', 'repoFullProfileApproved'):
        if field in value and type(value[field]) is not bool:
            raise InputError('invalid selection flag')
    if 'changedPaths' in value and 'changes' in value:
        raise InputError('ambiguous changes')
    paths = []
    if 'changedPaths' in value:
        paths = [_path(p) for p in _names(value['changedPaths'])]
    elif 'changes' in value:
        if not isinstance(value['changes'], list):
            raise InputError('invalid changes')
        for change in value['changes']:
            _object(change, ('status', 'path', 'old', 'new'), ('status',))
            status = change['status']
            required = {'status', 'old', 'new'} if status == 'rename' else {'status', 'path'}
            if status not in ('add', 'modify', 'delete', 'rename') or set(change) != required:
                raise InputError('invalid change')
            _extend(paths, [_path(change[k]) for k in (('old', 'new') if status == 'rename' else ('path',))])
    if len({path.casefold() for path in paths}) != len(set(paths)):
        raise InputError('case-colliding paths')
    profile = _name(value.get('profile', 'change'))
    if profile not in ('case', 'change', 'integration', 'release', 'operations'):
        raise InputError('unknown profile')
    required = _names(value.get('requiredInstanceIds', []))
    # Shape validation precedes rejection; aliases cannot admit excluded scope.
    if group == 'excluded':
        return _result('blocked', 4, 'excluded-scope')
    if requested is not None:
        if requested not in aliases:
            return _result('blocked', 4, 'unknown-scope-alias')
        group = aliases[requested]
        if group != scope['repositoryGroup']:
            return _result('blocked', 4, 'scope-registry-conflict')
    if group not in ('public', 'private', 'github-only'):
        return _result('blocked', 4, 'unknown-repository-group')
    target = _model(value['model'])
    base = _model(value.get('baseModel', value['model']))
    models = [base, target]
    # Casefold collisions are rejected across both revisions and every rule.
    all_paths = paths + [p for m in models for p in list(m['owners']) + list(m['rules'])]
    spellings = {}
    for path in all_paths:
        if path.casefold() in spellings and spellings[path.casefold()] != path:
            raise InputError('case-colliding paths')
        spellings[path.casefold()] = path
    prepare = []
    impact = []
    universe = []
    components = []
    guards = []
    for model in models:
        _extend(prepare, model['prepare'])
        _extend(impact, model['impact'])
        _extend(universe, model['universe'])
        _extend(components, model['components'])
        _extend(guards, model['guards'])
    if _cycle(prepare):
        return _result('invalid-input', 3, 'prepare-cycle')
    if any(i not in universe for edge in prepare for i in edge):
        raise InputError('unknown preparation instance')
    if any(i not in universe for i in required):
        raise InputError('unknown required instance')
    if profile != 'change' and not any(profile in m['profiles'] for m in models):
        return _result('blocked', 4, 'undeclared-profile')
    seeds = []
    unknown = []
    for path in paths:
        owners = [m['owners'][path] for m in models if path in m['owners']]
        _extend(seeds, owners)
        if not owners:
            unknown.append(path)
    fallback = 'none'
    if not value.get('baseAvailable', True) or unknown:
        if not value.get('repoFullProfileApproved', False):
            return _result('blocked', 4, 'unknown-path' if unknown else 'base-unavailable')
        if not any('full' in m['profiles'] for m in models):
            return _result('blocked', 4, 'undeclared-full-profile')
        full = []
        for m in models:
            _extend(full, m['profiles'].get('full', []))
        if set(full) != set(universe):
            return _result('blocked', 4, 'incomplete-full-profile')
        fallback = 'approved-repository-full'
        seeds = list(components)
    reached_set = set(_closure(seeds, impact))
    reached = [c for c in components if c in reached_set]
    selected = list(guards)
    for component in reached:
        for model in models:
            _extend(selected, model['mapping'].get(component, []))
    for path in paths:
        for model in models:
            _extend(selected, model['rules'].get(path, []))
    for model in models:
        _extend(selected, model['profiles'].get(profile, []))
        if fallback != 'none':
            _extend(selected, model['profiles']['full'] if 'full' in model['profiles'] else [])
    _extend(selected, required)
    selected = _closure(selected, prepare)
    if not selected:
        return _result('blocked', 4, 'empty-selection')
    omitted = [i for i in universe if i not in selected]
    return _result('plan-ready', 0, 'selection-ready', selected, omitted, reached, paths, fallback)
