"""Synthetic repositories for local execute (M8). No real repository, network or secret.

The manifest is the synthetic template with every check on this host's platform,
a synthetic adapter (a small Python script committed in the repository) and a
synthetic dataset file. The adapter reads ``src/main.txt`` for its behaviour:
each line ``<action> <logical check ID or *> [argument]``; without a matching
line it passes. It reads and writes only inside its own tree, except the
``linger`` descendant, which writes a marker at the given path if it survives.
"""
import copy
import hashlib
from pathlib import Path
from ci_contract import cjson
from ci_contract.arrays import normalize
from ci_contract.plan import MANIFEST, PROJECTION, POLICY, ENGINE_LOCK, variant_id
from synthetic_git import SyntheticGit

FIXTURES = Path(__file__).resolve().parent / 'fixtures'
ADAPTER_ID = 'synthetic-local-adapter'
ADAPTER_PATH = 'tools/adapter.py'
DATASET_PATH = 'data/dataset.txt'
# Declared (owned by app) but not in the base commit: a snapshot can include it explicitly.
EXTRA_PATH = 'src/extra.txt'
DATASET = b'synthetic dataset\n'
ADAPTER = b'''"""Synthetic adapter for the local execute tests (synthetic data only)."""
import json
import os
import subprocess
import sys
import time

CASES = ['synthetic-case']
ALLOWED = {'TEMP', 'TMP', 'USERPROFILE', 'SYSTEMROOT', 'PATH', 'HOME', 'TMPDIR', 'CI_CONTRACT_REPORT'}


def actions(check):
    try:
        with open(os.path.join('src', 'main.txt'), encoding='utf-8') as handle:
            lines = handle.read().splitlines()
    except OSError:
        return {}
    found = {}
    for line in lines:
        parts = line.split(' ', 2)
        if len(parts) >= 2 and parts[1] in (check, '*'):
            found[parts[0]] = parts[2] if len(parts) == 3 else ''
    return found


def main():
    check = sys.argv[2]
    todo = actions(check)
    if 'sleep' in todo:
        time.sleep(60)
    if 'pause' in todo:
        time.sleep(float(todo['pause']))
    if 'linger' in todo:
        code = 'import sys, time; time.sleep(3); open(sys.argv[1], "wb").close()'
        subprocess.Popen([sys.executable, '-I', '-c', code, todo['linger']], stdin=subprocess.DEVNULL,
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    failed = 'fail' in todo
    if 'envcheck' in todo and (not set(os.environ) <= ALLOWED or os.path.exists('.git')):
        failed = True
    if 'undeclared' in todo and os.path.exists('private-user-config'):
        failed = True
    if 'mutate' in todo:
        with open(os.path.join('src', 'main.txt'), 'ab') as handle:
            handle.write(b'changed by the check\\n')
    path = os.environ['CI_CONTRACT_REPORT']
    if 'forge' in todo:
        # Try to answer for a later check: passing analysis reports beside this one's.
        forged = {'kind': 'ci-contract-adapter-report-v1', 'expectedCaseIds': [], 'executedCaseIds': [],
                  'passedCaseIds': [], 'failedCaseIds': [], 'skippedCases': [], 'collectionComplete': True,
                  'targetPaths': ['src/main.txt'], 'analysisCompleted': True, 'diagnosticCount': 0, 'payloads': []}
        for folder in (os.path.dirname(path), os.path.dirname(os.path.dirname(path))):
            for number in range(10):
                with open(os.path.join(folder, '%d.json' % number), 'w', encoding='utf-8') as handle:
                    json.dump(forged, handle)
    if 'noreport' in todo:
        return 0
    if 'malformed' in todo:
        with open(path, 'wb') as handle:
            handle.write(b'{"kind":')
        return 0
    value = {'kind': 'ci-contract-adapter-report-v1', 'expectedCaseIds': [], 'executedCaseIds': [],
             'passedCaseIds': [], 'failedCaseIds': [], 'skippedCases': [], 'collectionComplete': True,
             'targetPaths': [], 'analysisCompleted': False, 'diagnosticCount': None, 'payloads': []}
    if check == 'app.test':
        value.update(expectedCaseIds=CASES, executedCaseIds=CASES, passedCaseIds=[] if failed else CASES,
                     failedCaseIds=CASES if failed else [])
        if 'skip' in todo:
            value.update(executedCaseIds=[], passedCaseIds=[],
                         skippedCases=[{'id': 'synthetic-case', 'reasonCode': 'synthetic-skip'}])
    elif check == 'app.generate':
        if 'nopayload' not in todo:
            os.makedirs('build', exist_ok=True)
            with open(os.path.join('build', 'payload.bin'), 'wb') as handle:
                handle.write(b'synthetic payload\\n')
        value['payloads'] = [{'artifactId': 'synthetic-payload', 'path': 'build/payload.bin'}]
    else:
        value.update(targetPaths=['src/main.txt'], analysisCompleted=True, diagnosticCount=1 if failed else 0)
    if 'incomplete' in todo:
        value.update(collectionComplete=False)
    if 'shape' in todo:
        value['executedCaseIds'] = 'synthetic-case'
    with open(path, 'w', encoding='utf-8') as handle:
        json.dump(value, handle, sort_keys=True, separators=(',', ':'))
    return 1 if failed else 0


if __name__ == '__main__':
    sys.exit(main())
'''
HOST = {'kind': 'ci-contract-local-host-v1',
        'adapters': [{'id': ADAPTER_ID, 'runner': 'python', 'entry': ADAPTER_PATH}],
        'datasets': [{'id': 'synthetic-dataset', 'path': DATASET_PATH}],
        'capabilities': []}


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def host(**changes):
    return dict(copy.deepcopy(HOST), **changes)


GENERATE_REQUIREMENT = {'checkIds': ['app.generate'], 'coverage': 'new-gap',
                        'externalReferences': ['SYNTHETIC-app.generate'], 'id': 'req.app.generate',
                        'origins': ['synthetic-fixture'], 'purpose': 'Synthetic app.generate', 'releaseRequired': False}


def quality_projection(generation=False):
    """The synthetic quality projection bytes; with ``generation`` it also maps app.generate."""
    data = (FIXTURES / 'synthetic-quality-projection.json').read_bytes()
    if not generation:
        return data
    projection = cjson.loads(data)
    projection['requirements'].append(copy.deepcopy(GENERATE_REQUIREMENT))
    projection['mappings'].append({'applicability': 'change', 'classification': 'new-gap', 'exceptionIds': [],
                                   'externalReference': 'SYNTHETIC-app.generate', 'logicalCheckIds': ['app.generate'],
                                   'purpose': 'Synthetic app.generate', 'requirementId': 'req.app.generate'})
    return cjson.dumps(normalize(projection))


def execute_manifest(os_name, arch, *, foreign=None, capabilities=None, timeout=10, network='none',
                     adapter=ADAPTER, generation=False):
    """The template manifest with every check on (os_name, arch) and the synthetic adapter.

    ``foreign`` adds a second app.test variant on another OS; ``capabilities``
    maps a logical check ID to its required capabilities; ``generation`` adds
    app.generate (payload synthetic-payload), on which app.test depends (use it
    with ``quality_projection(generation=True)``).
    """
    manifest = cjson.loads((FIXTURES / 'synthetic-manifest-template.json').read_bytes())
    template = manifest['checks'][0]['variants'][0]
    if generation:
        test = next(check for check in manifest['checks'] if check['id'] == 'app.test')
        generate = copy.deepcopy(test)
        generate.update(id='app.generate', kind='generation', requirementIds=['req.app.generate'], dependsOn=[])
        generate['proofPolicy'] = dict(generate['proofPolicy'], expectedCaseIds=[], expectedTargetPaths=[],
                                       expectedPayloadIds=['synthetic-payload'])
        manifest['checks'].append(generate)
        test['dependsOn'] = ['app.generate']
        manifest['requirements'].append(copy.deepcopy(GENERATE_REQUIREMENT))
        for mapping in manifest['selectionModel']['checkMappings']:
            if 'app' in mapping['componentIds']:
                mapping['logicalCheckIds'].append('app.generate')
        for component in manifest['selectionModel']['components']:
            if component['id'] == 'app':
                component['broadLogicalCheckIds'].append('app.generate')

    def variant(system):
        value = copy.deepcopy(template)
        value.update(os=system, arch=arch)
        value['dataset']['sha256'] = sha256(DATASET)
        return value
    for check in manifest['checks']:
        check.update(adapter=ADAPTER_ID, adapterSha256=sha256(adapter), argv=[ADAPTER_ID, check['id']],
                     timeoutSeconds=timeout, network=network,
                     requiredCapabilities=copy.deepcopy((capabilities or {}).get(check['id'], [])))
        check['variants'] = [variant(os_name)]
        if foreign is not None and check['id'] == 'app.test':
            check['variants'].append(variant(foreign))
    ids = sorted({variant_id(v) for check in manifest['checks'] for v in check['variants']})
    graph = manifest['selectionModel']
    for item in graph['inputRules'] + graph['impactEdges'] + graph['checkMappings']:
        item['condition']['variantIds'] = list(ids)
    condition = {'profiles': ['change'], 'variantIds': list(ids)}
    graph['inputRules'] += [
        {'id': 'synthetic-rule-adapter', 'path': ADAPTER_PATH, 'role': 'tool', 'componentIds': ['controls'],
         'sides': 'base-and-target', 'condition': copy.deepcopy(condition)},
        {'id': 'synthetic-rule-dataset', 'path': DATASET_PATH, 'role': 'fixture', 'componentIds': ['app'],
         'sides': 'base-and-target', 'condition': copy.deepcopy(condition)},
        {'id': 'synthetic-rule-extra', 'path': EXTRA_PATH, 'role': 'source', 'componentIds': ['app'],
         'sides': 'base-and-target', 'condition': copy.deepcopy(condition)}]
    return manifest


def execute_history(directory, manifest, *, adapter=ADAPTER, projection=None):
    """A synthetic repository: anchor, then a base commit with the manifest and the adapter."""
    git = SyntheticGit(directory)
    quality = quality_projection() if projection is None else projection
    anchor = git.commit({PROJECTION: ('100644', quality)}, message='synthetic quality anchor')
    manifest = copy.deepcopy(manifest)
    manifest['qualityProjectionRef'].update(commit=anchor, sha256=hashlib.sha256(quality).hexdigest())
    files = {MANIFEST: ('100644', cjson.dumps(normalize(manifest))), PROJECTION: ('100644', quality),
             POLICY: ('100644', (FIXTURES / 'synthetic-policy.json').read_bytes()),
             ENGINE_LOCK: ('100644', (FIXTURES / 'synthetic-engine-lock.json').read_bytes()),
             'src/main.txt': ('100644', b'synthetic base\n'),
             'docs/readme.md': ('100644', b'synthetic docs\n'),
             'bin/helper': ('100644', b'synthetic helper\n'),
             ADAPTER_PATH: ('100644', adapter), DATASET_PATH: ('100644', DATASET)}
    base = git.commit(files, parents=(anchor,), message='synthetic base')
    return git, base, files


def target_files(files, text):
    changed = dict(files)
    changed['src/main.txt'] = ('100644', text)
    return changed


def write_tree(directory, files):
    for path, (_, data) in files.items():
        target = Path(directory).joinpath(*path.split('/'))
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
