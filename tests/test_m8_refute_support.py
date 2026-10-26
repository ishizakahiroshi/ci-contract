"""Synthetic repository and adapter for the M8 refutation tests (synthetic data only).

The adapter behaves like tests/synthetic_execute.py (actions from lines of
``src/main.txt``: ``<action> <logical check ID or *> [argument]``) and adds the
actions the refutation needs. It reads and writes only inside its own tree,
except ``breakhome``, which removes the parent of its private home.
"""
import tempfile
from pathlib import Path
from ci_contract.execute import execute, host_platform
from ci_contract.plan import build_plan
from synthetic_claim import Clock, Workspace
from synthetic_execute import execute_history, execute_manifest, host, target_files

IDENTITY = host_platform()

ADAPTER = rb'''# Synthetic refutation adapter (synthetic data only).
import json
import os
import shutil
import sys
import time

FORGED = False
CASES = ['synthetic-case']
ME = os.path.join('tools', 'adapter.py')


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
    with open(ME, 'rb') as handle:
        own = handle.read()
    if FORGED:
        # This copy answers for one check without doing its work, then restores the pinned bytes.
        with open(ME, 'wb') as handle:
            handle.write(own.replace(b'FORGED = ' + b'True', b'FORGED = ' + b'False', 1))
        todo = {}
    elif 'swap' in todo:
        with open(ME, 'wb') as handle:
            handle.write(own.replace(b'FORGED = ' + b'False', b'FORGED = ' + b'True', 1))
    if 'pause' in todo:
        time.sleep(float(todo['pause']))
    if 'dirdecl' in todo:
        os.remove(todo['dirdecl'])
        os.mkdir(todo['dirdecl'])
    if 'hardlink' in todo:
        os.link(todo['hardlink'], todo['hardlink'] + '-link')
    if 'breakhome' in todo:
        parent = os.path.dirname(os.environ.get('USERPROFILE') or os.environ['HOME'])
        shutil.rmtree(parent)
        with open(parent, 'wb'):
            pass
    if 'readonly' in todo:
        os.makedirs('build', exist_ok=True)
        with open(os.path.join('build', 'readonly.txt'), 'wb') as handle:
            handle.write(b'synthetic output')
        os.chmod(os.path.join('build', 'readonly.txt'), 0o444)
    if 'oddname' in todo:
        os.makedirs('build', exist_ok=True)
        with open('\\\\?\\' + os.path.abspath('build') + '\\odd.', 'wb') as handle:
            handle.write(b'synthetic output')
    failed = 'fail' in todo
    value = {'kind': 'ci-contract-adapter-report-v1', 'expectedCaseIds': [], 'executedCaseIds': [],
             'passedCaseIds': [], 'failedCaseIds': [], 'skippedCases': [], 'collectionComplete': True,
             'targetPaths': [], 'analysisCompleted': False, 'diagnosticCount': None, 'payloads': []}
    if check == 'app.test':
        value.update(expectedCaseIds=CASES, executedCaseIds=CASES, passedCaseIds=[] if failed else CASES,
                     failedCaseIds=CASES if failed else [])
    else:
        value.update(targetPaths=['src/main.txt'], analysisCompleted=True, diagnosticCount=1 if failed else 0)
    if 'payload' in todo:
        value['payloads'] = [{'artifactId': name, 'path': 'src/main.txt'} for name in todo['payload'].split(',')]
    report = os.environ['CI_CONTRACT_REPORT']
    if 'linkreport' in todo:
        os.makedirs('build', exist_ok=True)
        report = os.path.join('build', 'report.json')
    with open(report, 'w', encoding='utf-8') as handle:
        json.dump(value, handle, sort_keys=True, separators=(',', ':'))
    if 'linkreport' in todo:
        os.link(report, os.environ['CI_CONTRACT_REPORT'])
    return 1 if failed else 0


if __name__ == '__main__':
    sys.exit(main())
'''


class Repository:
    """One synthetic repository whose pinned adapter is ADAPTER."""

    def __init__(self, root, name, timeout=10):
        manifest = execute_manifest(*IDENTITY, timeout=timeout, adapter=ADAPTER)
        self.git, self.base, self.files = execute_history(Path(root) / (name + '.git'), manifest, adapter=ADAPTER)
        self.root, self.name, self.count = Path(root), name, 0

    def plan(self, text):
        target = self.git.commit(target_files(self.files, text), parents=(self.base,), message='synthetic target')
        return build_plan(self.git.path, 'synthetic', self.base, target)

    def out(self):
        self.count += 1
        return str(self.root / ('%s-out-%d' % (self.name, self.count)))


class Base:
    """Mixin for unittest cases: one repository per class, one anchored journal per call."""

    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix='ci-contract-refute-')
        cls.root = Path(cls.temp.name)
        cls.repo = Repository(cls.root, 'refute')

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def space(self):
        space = Workspace()
        self.addCleanup(space.__exit__)
        (space.root / 'anchor').mkdir()
        space.anchored = space.journal(anchor_path=str(space.root / 'anchor' / 'journal.anchor'))
        return space

    def run_plan(self, plan, space=None, clock=None, out=None, journal=None, **options):
        space = self.space() if space is None else space
        out = self.repo.out() if out is None else out
        verdict = execute(plan, target='local', out=out, repo_path=str(self.repo.git.path), host=host(),
                          journal=space.anchored if journal is None else journal,
                          clock=Clock() if clock is None else clock, **options)
        return verdict, out, space

    @staticmethod
    def types(space):
        return [record['recordType'] for record in space.records()]
