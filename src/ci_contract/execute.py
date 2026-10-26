"""Local execution (M8): run a plan's checks on this computer under the trusted supervisor.

``execute`` is the only module that starts a check process. The supervisor is
the local collector (spec section 6): it starts each check, observes its exit,
time and cleanup, and reads the adapter's report itself; a check never writes
its own proof. The order is fixed:

1. Shapes (3), then refusals that need no Git and no process (4): the target,
   the operations profile (``blocked-contract``), local admission, and every
   check's platform, capabilities, network, shard, adapter and dataset against
   this host. A check this host cannot run is never dropped (c09).
2. The existing preflight, and the plan rebuilt from the repository's trusted
   base controls: a plan file that differs from the planner's output is
   blocked; a source that changed since planning is stale (5, c12).
3. The declared inputs are written to a private folder outside the receipt
   folder (commit: the target tree; snapshot: the declared inventory) and must
   reproduce the plan's digest. Each adapter entry and dataset is a declared
   input whose bytes must match the plan's digests.
4. The receipt folder, the journal (opened or created only now) and its claim:
   acquire, then ``claim.start_local``. A second run of the same request stops
   here; nothing is resumed from the journal.
5. Each check, in dependency order, as ``python -I -B <adapter entry> <argv>``
   with the private folder as its tree, a minimal environment (no ``GIT_*``,
   nothing else of the caller's), the check's time limit and confirmed cleanup
   of the whole process tree (a Windows job object; a POSIX session). A check
   that depends on generated payloads starts only with the measured bytes.
6. The execution, result and local supervisor ledger are verified with the M5
   verifier, recorded in the journal right after one more renewal of the
   claim, closed, and then written to the receipt folder.

Limits of v1, also in README: the network declaration is not enforced (only
``none`` runs, and nothing stops a check from opening a connection); a check
can read and write files outside its private folder (there is no sandbox); a
POSIX descendant that leaves its session or process group is not stopped; the
adapter's console output is kept in the receipt folder's ``logs`` and is not
evidence.
"""
import copy
import hashlib
import math
import os
import platform
import shutil
import stat
import subprocess
import sys
import tempfile
import time
from datetime import timedelta
from functools import lru_cache
from importlib.resources import files
from . import cjson, snapshot
from .arrays import normalize
from .errors import InputError, BlockedError
from .hashing import canonical_hash, domain_hash, raw_hash
from .inventory import validate_path
from .journal import AuthorityUnknown, LocalJournal
from .schema import load_schema, make_validator, validate

HOST_KIND = 'ci-contract-local-host-v1'
REPORT_KIND = 'ci-contract-adapter-report-v1'
LEDGER_KIND = 'local-supervisor-ledger-v1'
COLLECTOR_ID = 'local-supervisor'
OWNER_ID = 'local-supervisor'
AUTHORITY_KIND = 'local-single-supervisor-v1'
REPORT_VARIABLE = 'CI_CONTRACT_REPORT'
REQUEST_VALIDITY = timedelta(hours=24)
# The execution deadline is the sum of the check limits plus these allowances.
CHECK_ALLOWANCE_SECONDS = 5
EXECUTION_ALLOWANCE_SECONDS = 30
# Per declared file and per measurement (one after each check): the supervisor's own reading.
MEASURE_SECONDS_PER_FILE = 0.02
CLEANUP_SECONDS = 5
HEARTBEAT_SECONDS = 10.0
MAX_REPORT_BYTES = 1024 * 1024
MAX_PAYLOAD_BYTES = 256 * 1024 * 1024
# The result lists at most 10000 artifacts (schema); the payload bytes of one execution are capped.
MAX_ARTIFACTS = 10000
MAX_TOTAL_PAYLOAD_BYTES = 2 * 1024 * 1024 * 1024
RETENTION_DAYS = 7
# A fixed marker for a declared input that is missing or replaced after the run.
# It is never a source digest (those hash an inventory), so verify reports stale.
UNAVAILABLE_DIGEST = hashlib.sha256(b'ci-contract-local:declared-input-unavailable').hexdigest()
_CODES = {'accepted': 0, 'failed': 2, 'invalid-input': 3, 'blocked': 4, 'stale': 5,
          'cancelled': 6, 'timeout': 7, 'unknown': 8, 'error': 9}
_STATUSES = frozenset(('accepted', 'failed', 'blocked', 'stale', 'cancelled', 'timeout', 'unknown', 'error'))
_SYSTEMS = {'win32': 'windows', 'linux': 'linux', 'darwin': 'macos'}
_MACHINES = {'amd64': 'x86_64', 'x86_64': 'x86_64', 'arm64': 'aarch64', 'aarch64': 'aarch64'}
_HOST = {'type': 'object', 'additionalProperties': False,
         'required': ['kind', 'adapters', 'datasets', 'capabilities'],
         'properties': {
             'kind': {'const': HOST_KIND},
             'adapters': {'type': 'array', 'maxItems': 1000, 'items': {
                 'type': 'object', 'additionalProperties': False, 'required': ['id', 'runner', 'entry'],
                 'properties': {'id': {'$ref': '#/$defs/id'}, 'runner': {'const': 'python'},
                                'entry': {'$ref': '#/$defs/literalRepoPath'}}}},
             'datasets': {'type': 'array', 'maxItems': 1000, 'items': {
                 'type': 'object', 'additionalProperties': False, 'required': ['id', 'path'],
                 'properties': {'id': {'$ref': '#/$defs/id'}, 'path': {'$ref': '#/$defs/literalRepoPath'}}}},
             'capabilities': {'type': 'array', 'maxItems': 1000, 'items': {'$ref': '#/$defs/capability'}}}}
_COLLECTION = '#/$defs/proofCollection/properties/'
_REPORT = {'type': 'object', 'additionalProperties': False,
           'required': ['kind', 'expectedCaseIds', 'executedCaseIds', 'passedCaseIds', 'failedCaseIds',
                        'skippedCases', 'collectionComplete', 'targetPaths', 'analysisCompleted',
                        'diagnosticCount', 'payloads'],
           'properties': {
               'kind': {'const': REPORT_KIND},
               **{name: {'$ref': _COLLECTION + name} for name in (
                   'expectedCaseIds', 'executedCaseIds', 'passedCaseIds', 'failedCaseIds', 'skippedCases',
                   'collectionComplete', 'targetPaths', 'analysisCompleted', 'diagnosticCount')},
               'payloads': {'type': 'array', 'maxItems': 1000, 'items': {
                   'type': 'object', 'additionalProperties': False, 'required': ['artifactId', 'path'],
                   'properties': {'artifactId': {'$ref': '#/$defs/id'},
                                  'path': {'$ref': '#/$defs/literalRepoPath'}}}}}}


def _verdict(status, reason=None):
    verdict = {'status': status, 'exitCode': _CODES[status]}
    if reason is not None:
        verdict['reasonCode'] = reason
    return verdict


@lru_cache(maxsize=None)
def _validator(name):
    fragment = {'host': _HOST, 'report': _REPORT}[name]
    schema = load_schema()
    return make_validator(dict(fragment, **{'$schema': schema['$schema'], '$defs': schema['$defs']}))


def _conforms(name, value):
    try:
        cjson.dumps(value)
    except InputError:
        return False
    return next(_validator(name).iter_errors(value), None) is None


def check_host(host):
    """The trusted local host description: registered adapters, datasets and capabilities."""
    if not _conforms('host', host):
        raise InputError('invalid local host description')
    for field in ('adapters', 'datasets', 'capabilities'):
        names = [item['id'] for item in host[field]]
        if len(set(names)) != len(names):
            raise InputError('invalid local host description')
    # The platform is observed by the supervisor, never declared.
    if {item['id'] for item in host['capabilities']} & {'os', 'arch'}:
        raise InputError('invalid local host description')
    return host


def check_inputs(plan, host):
    """The shapes of the plan and the host description (invalid input, 3, before any decision)."""
    validate(plan)
    if plan['kind'] != 'plan':
        raise InputError('expected plan')
    normalize(plan, 'plan')
    check_host(host)


def host_platform():
    """This computer's (os, arch) in the contract's vocabulary, or blocked."""
    system = _SYSTEMS.get(sys.platform)
    arch = _MACHINES.get(platform.machine().lower())
    if system is None or arch is None:
        raise BlockedError('host-platform-unsupported')
    return system, arch


def _capabilities(host, identity):
    values = {item['id']: item['value'] for item in host['capabilities']}
    values.update(os=identity[0], arch=identity[1])
    return values


def precheck(plan, target, host, identity):
    """Refusals that need neither Git nor a process; every check is judged, none dropped."""
    if target not in ('local', 'github'):
        raise InputError('invalid execution target')
    if target == 'github':
        raise BlockedError('execute-target-unsupported')
    # Spec section 2: real provider reads, backup, publish and deploy keep their own contracts.
    if plan['profile'] == 'operations':
        raise BlockedError('blocked-contract')
    if plan['profile'] == 'release' and plan['source']['mode'] != 'commit':
        raise BlockedError('release-requires-commit')
    if not plan['repository']['localAllowed']:
        raise BlockedError('local-not-allowed')
    if not plan['checks']:
        raise BlockedError('plan-without-checks')
    system, arch = identity
    capabilities = _capabilities(host, identity)
    adapters = {item['id'] for item in host['adapters']}
    datasets = {item['id'] for item in host['datasets']}
    for check in plan['checks']:
        variant = check['variant']
        if variant['os'] != system or variant['arch'] != arch:
            raise BlockedError('capability-unavailable')
        if any(capabilities.get(item['id']) != item['value'] for item in check['requiredCapabilities']):
            raise BlockedError('capability-unavailable')
        # v1 provides no synthetic service or dependency mirror: refused, never run without it.
        if check['network'] != 'none':
            raise BlockedError('network-unavailable')
        # The adapter protocol carries no shard; a shard of a larger partition cannot be run.
        if variant['shard']['total'] != 1:
            raise BlockedError('shard-unsupported')
        if check['adapter'] not in adapters:
            raise BlockedError('adapter-unregistered')
        if variant['dataset']['id'] not in datasets:
            raise BlockedError('dataset-unregistered')


def _projection(repo_path, plan):
    from .gitsource import GitSource
    reference = plan['qualityProjectionRef']
    try:
        data = GitSource(repo_path).read_blob(plan['source']['baseCommit'], reference['path'], side='base')
    except BlockedError:
        return None
    value = cjson.loads(data)
    validate(value)
    return value


def reconstruct(plan, repo_path, snapshot_dir):
    """Rebuild the plan from the repository's trusted base controls and compare it.

    A commit plan is rebuilt from its embedded selection request (the same pins
    are matched against the base commit); a snapshot plan from its directory with
    the same explicit includes. A changed source is stale; any other difference
    is a plan that the planner did not produce: blocked.
    """
    from .gitsource import GitSource
    from .plan import build_plan
    from .request import StaleError, build_request_from_git
    source = plan['source']
    if source['mode'] == 'snapshot':
        if snapshot_dir is None:
            raise InputError('a snapshot plan needs its directory')
        base_paths = set(GitSource(repo_path).entries(source['baseCommit'], 'base'))
        include = sorted(entry['path'] for entry in source['inputs']
                         if entry['kind'] == 'file' and entry['path'] not in base_paths)
        try:
            rebuilt = build_plan(repo_path, plan['repository']['id'], source['baseCommit'], None,
                                 plan['profile'], snapshot_dir=snapshot_dir, include=include)
        except BlockedError as error:
            if error.reason_code == 'snapshot-input-missing':
                raise StaleError('source-changed') from None
            raise
    else:
        if snapshot_dir is not None:
            raise InputError('a commit plan has no snapshot directory')
        rebuilt = build_request_from_git(repo_path, plan['repository']['id'], cjson.dumps(plan['selectionRequest']),
                                         source['targetCommit'], plan['profile'])
    if rebuilt['source']['digest'] != source['digest']:
        raise StaleError('source-changed')
    if domain_hash('plan', rebuilt) != domain_hash('plan', plan):
        raise BlockedError('plan-reconstruction-mismatch')


def _order(checks):
    """Dependency order; within one layer, by instance ID.

    The plan's checks are a set (its hash does not depend on their order in the
    file), so the order of a layer must not depend on it either.
    """
    done, order = set(), []
    while len(order) < len(checks):
        ready = sorted((check for check in checks if check['id'] not in done and set(check['dependsOn']) <= done),
                       key=lambda check: check['id'])
        if not ready:
            raise InputError('cyclic or unknown check dependency')
        for check in ready:
            order.append(check)
            done.add(check['id'])
    return order


def _read_declared(directory, path):
    from .snapshot import _SnapshotReader
    try:
        return _SnapshotReader(directory).read(path)
    except BlockedError:
        return None


def _prepare_tree(plan, host, tree):
    """Adapter entries, datasets and working folders, all inside the private copy."""
    entries = {item['id']: item['entry'] for item in host['adapters']}
    datasets = {item['id']: item['path'] for item in host['datasets']}
    observed = {}
    for check in plan['checks']:
        data = _read_declared(tree, entries[check['adapter']])
        if data is None:
            raise BlockedError('adapter-entry-unavailable')
        if hashlib.sha256(data).hexdigest() != check['adapterSha256']:
            raise BlockedError('adapter-digest-mismatch')
        dataset = check['variant']['dataset']
        data = _read_declared(tree, datasets[dataset['id']])
        if data is None:
            raise BlockedError('dataset-unavailable')
        observed[check['id']] = hashlib.sha256(data).hexdigest()
        if observed[check['id']] != dataset['sha256']:
            raise BlockedError('dataset-mismatch')
        if check['cwd'] != '.':
            current = tree
            for part in validate_path(check['cwd']).split('/'):
                current = os.path.join(current, part)
                info = os.lstat(current) if os.path.lexists(current) else None
                if info is None or not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode):
                    raise BlockedError('check-cwd-unavailable')
    return entries, observed


# Process trees -------------------------------------------------------------------------

_WINDOWS = None


def _windows():
    """ctypes bindings for job objects, loaded on first use (Windows only)."""
    global _WINDOWS
    if _WINDOWS is None:
        import ctypes
        from ctypes import wintypes

        class Counters(ctypes.Structure):
            _fields_ = [(name, ctypes.c_ulonglong) for name in (
                'ReadOperationCount', 'WriteOperationCount', 'OtherOperationCount',
                'ReadTransferCount', 'WriteTransferCount', 'OtherTransferCount')]

        class Basic(ctypes.Structure):
            _fields_ = [('PerProcessUserTimeLimit', ctypes.c_longlong), ('PerJobUserTimeLimit', ctypes.c_longlong),
                        ('LimitFlags', wintypes.DWORD), ('MinimumWorkingSetSize', ctypes.c_size_t),
                        ('MaximumWorkingSetSize', ctypes.c_size_t), ('ActiveProcessLimit', wintypes.DWORD),
                        ('Affinity', ctypes.c_size_t), ('PriorityClass', wintypes.DWORD),
                        ('SchedulingClass', wintypes.DWORD)]

        class Extended(ctypes.Structure):
            _fields_ = [('BasicLimitInformation', Basic), ('IoInfo', Counters),
                        ('ProcessMemoryLimit', ctypes.c_size_t), ('JobMemoryLimit', ctypes.c_size_t),
                        ('PeakProcessMemoryUsed', ctypes.c_size_t), ('PeakJobMemoryUsed', ctypes.c_size_t)]

        class Accounting(ctypes.Structure):
            _fields_ = [('TotalUserTime', ctypes.c_longlong), ('TotalKernelTime', ctypes.c_longlong),
                        ('ThisPeriodTotalUserTime', ctypes.c_longlong), ('ThisPeriodTotalKernelTime', ctypes.c_longlong),
                        ('TotalPageFaultCount', wintypes.DWORD), ('TotalProcesses', wintypes.DWORD),
                        ('ActiveProcesses', wintypes.DWORD), ('TotalTerminatedProcesses', wintypes.DWORD)]

        kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
        ntdll = ctypes.WinDLL('ntdll')
        kernel32.CreateJobObjectW.argtypes = (ctypes.c_void_p, wintypes.LPCWSTR)
        kernel32.CreateJobObjectW.restype = wintypes.HANDLE
        kernel32.SetInformationJobObject.argtypes = (wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD)
        kernel32.SetInformationJobObject.restype = wintypes.BOOL
        kernel32.AssignProcessToJobObject.argtypes = (wintypes.HANDLE, wintypes.HANDLE)
        kernel32.AssignProcessToJobObject.restype = wintypes.BOOL
        kernel32.QueryInformationJobObject.argtypes = (wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p,
                                                       wintypes.DWORD, ctypes.POINTER(wintypes.DWORD))
        kernel32.QueryInformationJobObject.restype = wintypes.BOOL
        kernel32.TerminateJobObject.argtypes = (wintypes.HANDLE, wintypes.UINT)
        kernel32.TerminateJobObject.restype = wintypes.BOOL
        kernel32.CloseHandle.argtypes = (wintypes.HANDLE,)
        kernel32.CloseHandle.restype = wintypes.BOOL
        ntdll.NtResumeProcess.argtypes = (wintypes.HANDLE,)
        ntdll.NtResumeProcess.restype = ctypes.c_long
        _WINDOWS = (ctypes, kernel32, ntdll, Extended, Accounting)
    return _WINDOWS


class _JobTree:
    """Every process of one check in a Windows job object (killed when the job closes).

    The child is created suspended and assigned before it runs one instruction,
    so no descendant can start outside the job.
    """
    CREATE_FLAGS = 0x00000004  # CREATE_SUSPENDED

    def __init__(self, process):
        ctypes, kernel32, ntdll, Extended, _ = _windows()
        self.process, self.job = process, None
        job = kernel32.CreateJobObjectW(None, None)
        if not job:
            raise OSError('job object unavailable')
        try:
            limits = Extended()
            limits.BasicLimitInformation.LimitFlags = 0x00002000  # JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
            handle = int(process._handle)
            if (not kernel32.SetInformationJobObject(job, 9, ctypes.byref(limits), ctypes.sizeof(limits))
                    or not kernel32.AssignProcessToJobObject(job, handle)):
                raise OSError('job assignment failed')
            if ntdll.NtResumeProcess(handle) != 0:
                raise OSError('resume failed')
        except BaseException:
            kernel32.CloseHandle(job)  # also ends an assigned process (kill on close)
            raise
        self.job = job

    def stop(self):
        _, kernel32, _, _, _ = _windows()
        if self.job is not None:
            kernel32.TerminateJobObject(self.job, 1)
        else:
            self.process.kill()

    def active(self):
        ctypes, kernel32, _, _, Accounting = _windows()
        if self.job is None:
            return 0 if self.process.poll() is not None else 1
        accounting = Accounting()
        if not kernel32.QueryInformationJobObject(self.job, 1, ctypes.byref(accounting),
                                                  ctypes.sizeof(accounting), None):
            raise OSError('job query failed')
        return accounting.ActiveProcesses

    def close(self):
        _, kernel32, _, _, _ = _windows()
        if self.job is not None:
            kernel32.CloseHandle(self.job)
            self.job = None


class _SessionTree:
    """Every process of one check in a new POSIX session (its process group)."""
    CREATE_FLAGS = 0

    def __init__(self, process):
        self.process, self.group = process, process.pid

    def stop(self):
        import signal
        try:
            os.killpg(self.group, signal.SIGKILL)
        except ProcessLookupError:
            pass

    def active(self):
        """1 while a process of the group exists. Called only after the leader was reaped."""
        # A supervisor that is PID 1 or a subreaper inherits the stopped descendants:
        # reap them, or they stay in the group as zombies and cleanup never confirms.
        try:
            while os.waitpid(-self.group, os.WNOHANG)[0]:
                pass
        except ChildProcessError:
            pass
        try:
            os.killpg(self.group, 0)
        except ProcessLookupError:
            return 0
        return 1

    def close(self):
        pass


def _launch(command, cwd, env, log):
    if os.name == 'nt':
        process = subprocess.Popen(command, cwd=cwd, env=env, stdin=subprocess.DEVNULL, stdout=log,
                                   stderr=subprocess.STDOUT, creationflags=_JobTree.CREATE_FLAGS)
        try:
            return process, _JobTree(process)
        except OSError:
            process.kill()
            process.wait()
            raise
    process = subprocess.Popen(command, cwd=cwd, env=env, stdin=subprocess.DEVNULL, stdout=log,
                               stderr=subprocess.STDOUT, start_new_session=True)
    return process, _SessionTree(process)


def _settle(process, tree):
    """Stop every remaining process of the tree and confirm that none is left."""
    end = time.monotonic() + CLEANUP_SECONDS
    try:
        while True:
            if process.poll() is not None and tree.active() == 0:
                return True
            tree.stop()
            if time.monotonic() >= end:
                return False
            time.sleep(0.05)
    except OSError:
        return False


def _environment(home, report):
    """The child's whole environment: nothing of the caller's except the OS location."""
    if os.name == 'nt':
        environment = {'TEMP': home, 'TMP': home, 'USERPROFILE': home}
        root = os.environ.get('SYSTEMROOT')
        if root:
            environment.update(SYSTEMROOT=root, PATH=os.path.join(root, 'System32') + ';' + root)
    else:
        environment = {'HOME': home, 'TMPDIR': home, 'PATH': '/usr/bin:/bin'}
    environment[REPORT_VARIABLE] = report
    return environment


def _environment_names():
    return sorted(_environment('home', 'report'))


# Observations that do not change during one execution ------------------------------------

@lru_cache(maxsize=1)
def _engine_fingerprint():
    """The running engine: every Python and JSON file of the package, by path and bytes."""
    entries = []

    def walk(node, prefix):
        for child in sorted(node.iterdir(), key=lambda item: item.name):
            name = prefix + child.name
            if child.is_dir():
                if child.name != '__pycache__':
                    walk(child, name + '/')
            elif child.name.endswith(('.py', '.json')):
                entries.append([name, raw_hash(child.read_bytes())])
    walk(files('ci_contract'), '')
    return raw_hash(cjson.dumps(entries))


def _supervisor_policy():
    return raw_hash(cjson.dumps({
        'kind': 'local-supervisor-policy-v1', 'runner': ['python', '-I', '-B'],
        'environment': _environment_names(), 'reportVariable': REPORT_VARIABLE,
        'network': 'declared-none-not-enforced',
        'tree': 'windows-job-object' if os.name == 'nt' else 'posix-session',
        'cleanupSeconds': CLEANUP_SECONDS}))


@lru_cache(maxsize=1)
def _toolchain():
    with open(sys.executable, 'rb') as handle:
        binary = hashlib.sha256(handle.read()).hexdigest()
    return {'id': 'python', 'version': platform.python_version(), 'binarySha256': binary}


def _image(identity):
    details = {'os': identity[0], 'arch': identity[1], 'system': platform.system(),
               'release': platform.release(), 'version': platform.version(), 'python': platform.python_version()}
    version = (platform.system() + ' ' + platform.release()).strip() or 'unknown'
    return {'kind': 'local-host-fingerprint', 'name': 'local-supervisor-host', 'version': version[:512],
            'fingerprintSha256': raw_hash(cjson.dumps(details))}


class _Moments:
    """Document times from the supplied clock: whole UTC seconds that never go back.

    Once a time was read, a clock that fails keeps the last time and sets
    ``failed``: after the start every outcome is recorded, and the execution
    whose clock failed is unknown.
    """

    def __init__(self, clock):
        self.clock, self.last, self.failed = clock, None, False

    def __call__(self):
        from .claim import _now
        try:
            now = _now(self.clock).replace(microsecond=0)
        except InputError:
            if self.last is None:
                raise
            self.failed = True
            return self.last
        if self.last is not None and now < self.last:
            now = self.last
        self.last = now
        return now


def _text(moment):
    return moment.strftime('%Y-%m-%dT%H:%M:%SZ')


# One check -------------------------------------------------------------------------------

class _ClaimLost(Exception):
    """The claim could not be renewed during the supervisor's own work (unknown, 8)."""


class _Outcome:
    def __init__(self):
        self.receipt = None       # the check's result entry, or None (missing)
        self.artifacts = []       # artifact entries; the bytes are already in artifacts/
        self.stop = None          # None, or the terminal observation that ends the execution
        self.cleaned = True
        self.events = []


def _read_report(path):
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        return None
    except OSError:
        return None
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > MAX_REPORT_BYTES:
        return None
    try:
        with open(path, 'rb') as handle:
            data = handle.read(MAX_REPORT_BYTES + 1)
    except OSError:
        return None
    if len(data) > MAX_REPORT_BYTES:
        return None
    try:
        value = cjson.loads(data)
    except InputError:
        return None
    return value if _conforms('report', value) else None


class _Supervisor:
    def __init__(self, plan, execution, area, out, entries, datasets, identity, journal, clock, moments,
                 heartbeat_seconds):
        self.plan, self.execution, self.area, self.out = plan, execution, area, out
        self.tree = os.path.join(area, 'tree')
        self.entries, self.datasets, self.identity = entries, datasets, identity
        self.journal, self.clock, self.moments = journal, clock, moments
        self.heartbeat_seconds = heartbeat_seconds
        self.nonce = 'local-' + os.urandom(16).hex()
        self.image = _image(identity)
        self.produced = {}        # instance ID -> [artifact sha256] of generation checks
        self.produced_paths = {}  # instance ID -> [(tree path, sha256)] of generation checks
        self.artifact_ids = set()
        self.payload_bytes = 0
        self.renewed = time.monotonic()

    def _alive(self):
        from .claim import heartbeat
        try:
            observed = heartbeat(self.journal, self.execution['requestBinding']['requestId'], clock=self.clock)
        except OSError:
            return False  # the journal cannot record the renewal: like a lost claim
        finally:
            # Counted from the end: a renewal slower than the interval (a large journal) is
            # not repeated at every tick of the work that follows it.
            self.renewed = time.monotonic()
        return observed['status'] == 'leased'

    def tick(self):
        """Renew the claim during the supervisor's own long work (measurements, payload copies)."""
        if time.monotonic() - self.renewed >= self.heartbeat_seconds and not self._alive():
            raise _ClaimLost()

    def _generated_changed(self, check):
        """True when a generated payload this check depends on is no longer the measured bytes.

        All checks write one shared tree, so a check between a producer and its
        dependent can overwrite the payload path; the dependent's proof names the
        producer's digest, so it must start with exactly those bytes.
        """
        for dependency in check['dependsOn']:
            for path, digest in self.produced_paths.get(dependency, []):
                found = snapshot.stream_declared(self.tree, path, limit=MAX_PAYLOAD_BYTES, tick=self.tick)
                if found is None or found[0] != digest:
                    return True
        return False

    def _wait(self, process, seconds):
        end = time.monotonic() + seconds
        while True:
            remaining = end - time.monotonic()
            if remaining <= 0:
                return 'timeout'
            try:
                process.wait(timeout=min(remaining, self.heartbeat_seconds))
                return 'exited'
            except subprocess.TimeoutExpired:
                if not self._alive():
                    return 'claim-lost'

    def run(self, index, check):
        outcome = _Outcome()
        events = outcome.events
        # The claim must be live when each check starts: an expired or orphaned lease
        # means the journal no longer lets this attempt run.
        if not self._alive():
            events.append({'event': 'claim-lost'})
            outcome.stop = 'unavailable'
            return outcome
        try:
            changed = self._generated_changed(check)
        except _ClaimLost:
            events.append({'event': 'claim-lost'})
            outcome.stop = 'unavailable'
            return outcome
        if changed:
            events.append({'event': 'generated-input-changed'})
            outcome.stop = 'unavailable'
            return outcome
        entry = self.entries[check['adapter']]
        cwd = self.tree if check['cwd'] == '.' else os.path.join(self.tree, *check['cwd'].split('/'))
        command = [sys.executable, '-I', '-B', os.path.join(self.tree, *entry.split('/')), *check['argv']]
        log_path = os.path.join(self.out, 'logs', '%02d-%s.log' % (index, check['logicalCheckId']))
        started = self.moments()
        events.append({'event': 'start', 'at': _text(started), 'instanceId': check['id'], 'argv': list(check['argv'])})
        try:
            # A new folder per check, named only now: an earlier check (whose processes have
            # all ended) cannot have written this check's report or left files in its home.
            report = os.path.join(tempfile.mkdtemp(prefix='report-', dir=os.path.join(self.area, 'reports')),
                                  'report.json')
            home = tempfile.mkdtemp(prefix='home-', dir=os.path.join(self.area, 'home'))
            with open(log_path, 'xb') as log:
                process, tree = _launch(command, cwd, _environment(home, report), log)
        except OSError:
            events.append({'event': 'launch-failed'})
            outcome.stop = 'unavailable'
            return outcome
        state = 'claim-lost'
        try:
            state = self._wait(process, check['timeoutSeconds'])
        except OSError:
            pass  # the claim could not be renewed: like a lost claim, unknown
        finally:
            if state != 'exited':
                try:
                    tree.stop()
                except OSError:
                    pass  # _settle stops again and confirms, or reports cleanup unconfirmed
            outcome.cleaned = _settle(process, tree)
            tree.close()
        try:
            return self._observe(check, outcome, state, process.returncode, report, entry, started)
        except _ClaimLost:
            events.append({'event': 'claim-lost'})
            outcome.stop = 'unavailable'
            return outcome
        except (OSError, MemoryError):
            events.append({'event': 'observation-failed'})
            outcome.stop = 'unavailable'
            return outcome

    def _observe(self, check, outcome, state, code, report, entry, started):
        events = outcome.events
        completed = self.moments()
        events.append({'event': state, 'at': _text(completed), 'exitCode': code,
                       'cleanupConfirmed': outcome.cleaned})
        if not outcome.cleaned:
            outcome.stop = 'unavailable'
            return outcome
        if state == 'timeout':
            outcome.stop = 'check-timeout'
            return outcome
        if state == 'claim-lost' or code is None:
            outcome.stop = 'unavailable'
            return outcome
        signal_name = None
        if code < 0:
            import signal
            try:
                signal_name = signal.Signals(-code).name
            except ValueError:
                signal_name = 'signal-' + str(-code)
        value = _read_report(report)
        events.append({'event': 'report', 'valid': value is not None})
        if value is None or signal_name is not None:
            outcome.stop = 'unavailable'
            return outcome
        built = self._receipt(check, value, entry, started, completed, code, events)
        if built is None:
            events.append({'event': 'report-rejected'})
            outcome.stop = 'unavailable'
            return outcome
        outcome.receipt, outcome.artifacts = built
        return outcome

    def _copy_payload(self, item, written):
        """Copy one payload from the tree to artifacts/ in chunks: (sha256, size), or None (unusable)."""
        folder = os.path.join(self.out, 'artifacts')
        try:
            os.mkdir(folder)
        except FileExistsError:
            pass
        target = os.path.join(folder, item['artifactId'])
        limit = min(MAX_PAYLOAD_BYTES, MAX_TOTAL_PAYLOAD_BYTES - self.payload_bytes)
        with open(target, 'xb') as handle:
            written.append(target)

            def sink(chunk):
                if handle.write(chunk) != len(chunk):
                    raise OSError('incomplete write')
            return snapshot.stream_declared(self.tree, item['path'], limit=limit, sink=sink, tick=self.tick)

    def _receipt(self, check, report, entry, started, completed, code, events):
        """The check's result entry from the supervisor's observations and the adapter's report.

        Each payload is copied to the receipt folder's artifacts/ as it is measured
        (no payload's bytes are kept in memory); a report that makes no receipt
        leaves none of its files there.
        """
        written, ids, size_before = [], [], self.payload_bytes
        built = None
        try:
            built = self._build_receipt(check, report, entry, started, completed, code, events, written, ids)
            return built
        finally:
            if built is None:
                for path in written:
                    try:
                        os.remove(path)
                    except OSError:
                        pass
                try:
                    os.rmdir(os.path.join(self.out, 'artifacts'))  # only when no other check's file is in it
                except OSError:
                    pass
                self.artifact_ids.difference_update(ids)
                self.payload_bytes = size_before

    def _build_receipt(self, check, report, entry, started, completed, code, events, written, ids):
        plan, execution = self.plan, self.execution
        policy, variant = check['proofPolicy'], check['variant']
        source_digest = plan['source']['digest']
        plan_sha = execution['planSha256']
        generated = sorted({digest for dependency in check['dependsOn'] for digest in self.produced.get(dependency, [])})
        payloads, artifacts, paths = [], [], []
        for item in report['payloads']:
            # The artifact ID is the file name in the receipt folder's artifacts/: it must be
            # a valid inventory path segment (no reserved device name, no trailing dot or
            # space) and unique in the execution, which lists at most MAX_ARTIFACTS.
            try:
                if validate_path(item['artifactId']) != item['artifactId']:
                    return None
                validate_path(item['path'])
            except InputError:
                return None
            if item['artifactId'] in self.artifact_ids or len(self.artifact_ids) >= MAX_ARTIFACTS:
                return None
            self.artifact_ids.add(item['artifactId'])
            ids.append(item['artifactId'])
            found = self._copy_payload(item, written)
            if found is None:
                return None
            digest, size = found
            self.payload_bytes += size
            paths.append((item['path'], digest))
            payloads.append({'artifactId': item['artifactId'], 'sha256': digest, 'sizeBytes': size,
                             'os': self.identity[0], 'arch': self.identity[1], 'producerInstanceId': check['id'],
                             'inputDigests': sorted({source_digest, *generated})})
            artifacts.append({'id': item['artifactId'], 'sha256': digest, 'sizeBytes': size,
                              'sourceDigest': source_digest, 'planSha256': plan_sha, 'producerCheckId': check['id'],
                              'mediaType': 'application/octet-stream', 'retentionDays': RETENTION_DAYS,
                              'privacy': 'private'})
        collection = {name: copy.deepcopy(report[name]) for name in (
            'expectedCaseIds', 'executedCaseIds', 'passedCaseIds', 'failedCaseIds', 'skippedCases',
            'collectionComplete', 'targetPaths', 'analysisCompleted', 'diagnosticCount')}
        collection['enumerationContractSha256'] = policy['enumerationContractSha256']
        attempt = execution['requestBinding']['attemptAuthority']['attemptNumber']
        proof = {'proofVersion': 'embedded-proof-v1',
                 'identity': {'requestId': execution['requestBinding']['requestId'],
                              'executionId': execution['executionId'], 'planSha256': plan_sha,
                              'claimSha256': execution['claimSha256'], 'instanceId': check['id'],
                              'logicalCheckId': check['logicalCheckId'], 'adapterSha256': check['adapterSha256'],
                              'sourceDigest': source_digest, 'generatedInputDigests': generated, 'attempt': attempt},
                 'kind': check['kind'], 'variant': copy.deepcopy(variant),
                 'runtime': {'os': self.identity[0], 'arch': self.identity[1], 'toolchains': [_toolchain()],
                             'datasetSha256': self.datasets[check['id']], 'serviceFixtureDigests': [],
                             'imageIdentity': self.image},
                 'invocation': {'adapterEntry': entry, 'argv': list(check['argv']), 'cwd': check['cwd'],
                                'startedAt': _text(started), 'completedAt': _text(completed),
                                'exitCode': code, 'signal': None},
                 'collection': collection, 'payloads': payloads,
                 'collector': {'collectorId': COLLECTOR_ID, 'collectorBinarySha256': _engine_fingerprint(),
                               'collectorPolicySha256': _supervisor_policy(),
                               'eventLogSha256': raw_hash(cjson.dumps(events)), 'target': 'local',
                               'runId': None, 'jobId': None, 'attempt': attempt, 'workerNonce': self.nonce,
                               'observationBoundary': 'supervised-process-and-adapter-protocol',
                               'retentionDays': RETENTION_DAYS},
                 'cleanup': {'childrenStopped': True, 'resourcesReleased': True, 'unresolvedResourceIds': []}}
        if code != 0:
            status = 'failed'
        elif check['kind'] == 'test' and not report['executedCaseIds']:
            status = 'skipped'  # nothing executed is never a pass
        else:
            status = 'passed'
        receipt = {'id': check['id'], 'kind': check['kind'], 'status': status, 'exitCode': code,
                   'executedTests': len(report['executedCaseIds']) if check['kind'] == 'test' else None,
                   'proofSha256': canonical_hash(proof), 'adapterSha256': check['adapterSha256'],
                   'cleanupConfirmed': True, 'logicalCheckId': check['logicalCheckId'],
                   'variant': copy.deepcopy(variant), 'proof': proof}
        # The report must make a valid receipt for this check's kind (else it is unusable).
        try:
            validate({'kind': 'result', 'contractVersion': '1.0', 'executionId': execution['executionId'],
                      'executionSha256': '0' * 64, 'planSha256': plan_sha, 'engineSha256': '0' * 64,
                      'sourceDigestBefore': source_digest, 'sourceDigestAfter': source_digest, 'target': 'local',
                      'status': 'unknown', 'exitCode': 8, 'checks': [receipt], 'missingCheckIds': [],
                      'unresolvedRequirementIds': [], 'pendingChildren': 0, 'cleanupConfirmed': True,
                      'evidenceOrigin': 'local-receipt', 'artifacts': artifacts,
                      'completedAt': _text(completed), 'requestBinding': _result_binding(execution)})
            normalize({'kind': 'result', 'checks': [receipt]}, 'result')
        except InputError:
            return None
        if check['kind'] == 'generation':
            self.produced[check['id']] = [item['sha256'] for item in artifacts]
            self.produced_paths[check['id']] = paths
        return receipt, artifacts


def _result_binding(execution):
    binding = execution['requestBinding']
    authority = binding['attemptAuthority']
    return {**{key: binding[key] for key in ('requestId', 'requestDigest', 'scopeKey', 'authorityKind')},
            **{key: authority[key] for key in ('attemptNumber', 'fence', 'adoptionRecordSha256')}}


def _write(path, data):
    with open(path, 'xb') as handle:
        if handle.write(data) != len(data):
            raise OSError('incomplete write')


# The command -----------------------------------------------------------------------------

def _check_journal(journal):
    if type(journal) is not LocalJournal or journal.anchor_path is None:
        raise InputError('an anchored journal is required')


def execute(plan, *, target, out, repo_path, host, clock, journal=None, journal_factory=None, snapshot_dir=None,
            request_id=None, platform_identity=None, heartbeat_seconds=HEARTBEAT_SECONDS):
    """Run the plan's checks here and return the final verdict {status, exitCode[, reasonCode]}.

    ``host`` is the trusted local host description (``check_host``); ``journal``
    an anchored LocalJournal outside every repository root, or ``journal_factory``
    a callable that opens or creates it, called at step 4 only (so a refusal of
    steps 1 to 3 creates no journal); ``clock`` the UTC clock of the journal
    decisions and of every document time. The receipt folder ``out`` must not
    exist. ``platform_identity`` replaces the observed (os, arch) for tests of a
    host that cannot run a check. An operating-system error before the attempt
    starts is error 9 (``local-io-failed``).
    """
    from .request import StaleError, preflight
    area = None
    try:
        check_inputs(plan, host)
        for path in (out, repo_path):
            if type(path) is not str or not os.path.isabs(path):
                raise InputError('paths must be absolute')
        if snapshot_dir is not None and (type(snapshot_dir) is not str or not os.path.isabs(snapshot_dir)):
            raise InputError('paths must be absolute')
        if (journal is None) == (journal_factory is None):
            raise InputError('an anchored journal is required')
        if journal is not None:
            _check_journal(journal)
        elif not callable(journal_factory):
            raise InputError('an anchored journal is required')
        if type(heartbeat_seconds) not in (int, float) or not 0 < heartbeat_seconds <= 20:
            raise InputError('invalid heartbeat interval')
        plan_sha = domain_hash('plan', plan)
        request_id = 'local-' + plan_sha if request_id is None else request_id
        if not _conforms_id(request_id):
            raise InputError('invalid request id')
        identity = host_platform() if platform_identity is None else platform_identity
        precheck(plan, target, host, identity)
        _order(plan['checks'])
        verdict = preflight(plan, 'local', quality_projection=_projection(repo_path, plan))
        if verdict['exitCode']:
            return verdict
        reconstruct(plan, repo_path, snapshot_dir)
        from .snapshot import materialize
        area = tempfile.mkdtemp(prefix='ci-contract-execute-')
        before = materialize(plan['source'], os.path.join(area, 'tree'),
                             repo_path=repo_path if plan['source']['mode'] == 'commit' else None,
                             snapshot_dir=snapshot_dir)
        entries, datasets = _prepare_tree(plan, host, os.path.join(area, 'tree'))
        os.mkdir(os.path.join(area, 'reports'))
        os.mkdir(os.path.join(area, 'home'))
        try:
            os.mkdir(out)
        except OSError:
            raise InputError('receipt folder unavailable') from None
        if journal is None:
            try:
                journal = journal_factory()
                _check_journal(journal)
            except BaseException:
                os.rmdir(out)  # the refusal leaves nothing of step 4
                raise
        return _execute(plan, plan_sha, before, area, out, host, entries, datasets, identity, journal, clock,
                        request_id, heartbeat_seconds)
    except InputError:
        return _verdict('invalid-input')
    except StaleError as error:
        return _verdict('stale', error.reason_code)
    except BlockedError as error:
        return _verdict('blocked', error.reason_code)
    except AuthorityUnknown as error:
        return _verdict('unknown', error.reason_code)
    except OSError:
        return _verdict('error', 'local-io-failed')
    finally:
        if area is not None:
            _remove_tree(area)


def _remove_tree(path):
    """Remove the private folder, including read-only files and names Windows refuses."""
    def retry(function, name, _):
        try:
            os.chmod(os.path.dirname(name), 0o700)
            if not os.path.islink(name):
                os.chmod(name, 0o700)
            function(name)
        except OSError:
            pass
    path = os.path.abspath(path)
    if os.name == 'nt' and not path.startswith('\\\\?\\'):
        path = '\\\\?\\' + path  # names with a trailing dot or space are reachable only so
    shutil.rmtree(path, onexc=retry)


def _conforms_id(value):
    from .journal import conforms
    return conforms('id', value)


def _execute(plan, plan_sha, before, area, out, host, entries, datasets, identity, journal, clock, request_id,
             heartbeat_seconds):
    from .claim import acquire, close, ingest_receipt, observe_completion, start_local
    from .request_binding import make_request_binding, request_digest, scope_key
    from .snapshot import digest_after
    from .verify import verify
    moments = _Moments(clock)
    started = None
    try:
        now = moments()
        binding = make_request_binding(plan, request_id=request_id, authority_id=journal.authority_id,
                                       target='local', trust='trusted', workflow_commit=None,
                                       created_at=_text(now), expires_at=_text(now + REQUEST_VALIDITY),
                                       authority_kind=AUTHORITY_KIND)
        acquired = acquire(journal, binding, owner_id=OWNER_ID, clock=clock)
        if acquired['status'] == 'coalesced':
            return _verdict('blocked', 'request-coalesced')
        if acquired['status'] != 'acquired':
            return acquired
        started = start_local(journal, binding, clock=clock)
        if started['status'] != 'started':
            return started
    finally:
        if started is None or started['status'] != 'started':
            os.rmdir(out)  # nothing was written; no execution exists
    # From here the attempt exists: every outcome is written and recorded as a receipt.
    begin = moments()
    budget = sum(check['timeoutSeconds'] + CHECK_ALLOWANCE_SECONDS for check in plan['checks'])
    # The supervisor reads every declared file after each check (the last time for the result).
    files = sum(1 for entry in plan['source']['inputs'] if entry['kind'] == 'file')
    measuring = math.ceil(MEASURE_SECONDS_PER_FILE * files * len(plan['checks']))
    deadline = begin + timedelta(seconds=budget + measuring + EXECUTION_ALLOWANCE_SECONDS)
    authority = started['attemptAuthority']
    capabilities = sorted(({'id': key, 'value': value} for key, value in _capabilities(host, identity).items()),
                          key=lambda item: item['id'])
    execution = {'kind': 'execution', 'contractVersion': '1.0',
                 'executionId': 'local-' + raw_hash(authority['adoptionRecordSha256'].encode('ascii')),
                 'planSha256': plan_sha, 'plan': copy.deepcopy(plan), 'target': 'local',
                 'capabilities': capabilities, 'github': None, 'startedAt': _text(begin),
                 'deadlineAt': _text(deadline), 'claimSha256': domain_hash('claim', started['claim']),
                 'requestBinding': {'requestId': request_id, 'requestDigest': request_digest(binding),
                                    'scopeKey': scope_key(binding), 'attemptAuthority': authority,
                                    'authorityKind': AUTHORITY_KIND}}
    from .plan import plan_bytes
    supervisor = _Supervisor(plan, execution, area, out, entries, datasets, identity, journal, clock, moments,
                             heartbeat_seconds)
    receipts, artifacts, missing, events = [], [], [], {}
    terminal, cleaned = 'completed', True
    order = _order(plan['checks'])
    tree = os.path.join(area, 'tree')
    try:
        _write(os.path.join(out, 'plan.json'), plan_bytes(plan))
        _write(os.path.join(out, 'execution.json'), cjson.dumps(execution))
        os.mkdir(os.path.join(out, 'logs'))
    except OSError:
        terminal, missing = None, [check['id'] for check in order]  # nothing runs; recorded as unknown
    for index, check in enumerate(order if terminal == 'completed' else ()):
        try:
            outcome = supervisor.run(index, check)
        except (OSError, MemoryError):
            outcome = _Outcome()
            outcome.stop, outcome.cleaned = 'unavailable', False
        events[check['id']] = outcome.events
        cleaned = cleaned and outcome.cleaned
        if outcome.receipt is None:
            missing.extend(item['id'] for item in order[index:])
            terminal = 'check-timeout' if outcome.stop == 'check-timeout' else None
            break
        receipts.append(outcome.receipt)
        artifacts.extend(outcome.artifacts)
        if moments() > deadline:
            missing.extend(item['id'] for item in order[index + 1:])
            terminal = 'deadline-exceeded'
            break
        # Every later check must start with the planned inputs, its adapter and dataset
        # included: a check that changed one ends the execution (stale), before the next starts.
        if index + 1 < len(order):
            try:
                changed = digest_after(plan['source'], tree, tick=supervisor.tick) != before
            except (_ClaimLost, MemoryError):
                changed, terminal = True, None
            if changed:
                missing.extend(item['id'] for item in order[index + 1:])
                break
    try:
        try:
            after = digest_after(plan['source'], tree, tick=supervisor.tick)
        except _ClaimLost:
            terminal = None  # still measured: the result states the inputs as they are
            after = digest_after(plan['source'], tree)
    except MemoryError:
        terminal, after = None, None
    after = UNAVAILABLE_DIGEST if after is None else after
    if moments.failed:
        terminal = None  # a clock that failed after the start: unknown
    elif terminal == 'completed' and moments() > deadline:
        terminal = 'deadline-exceeded'
    result_binding = _result_binding(execution)

    def documents(terminal):
        """The result and ledger of this terminal observation, and the verifier's problem with them."""
        completed = moments()
        if terminal == 'check-timeout' or terminal == 'deadline-exceeded':
            status = 'timeout'
        elif terminal is None or not cleaned:
            status = 'unknown'
        elif after != before:
            status = 'stale'
        elif any(receipt['status'] == 'failed' for receipt in receipts):
            status = 'failed'
        elif all(receipt['status'] == 'passed' for receipt in receipts):
            status = 'accepted'
        else:
            status = 'blocked'
        result = {'kind': 'result', 'contractVersion': '1.0', 'executionId': execution['executionId'],
                  'executionSha256': domain_hash('execution', execution), 'planSha256': plan_sha,
                  'engineSha256': plan['engine']['bundleSha256'], 'sourceDigestBefore': before,
                  'sourceDigestAfter': after, 'target': 'local', 'status': status, 'exitCode': _CODES[status],
                  'checks': receipts, 'missingCheckIds': missing, 'unresolvedRequirementIds': [],
                  'pendingChildren': 0 if cleaned else 1, 'cleanupConfirmed': cleaned,
                  'evidenceOrigin': 'local-receipt', 'artifacts': list(artifacts), 'completedAt': _text(completed),
                  'requestBinding': result_binding}
        ledger = {'kind': LEDGER_KIND, 'collectorId': COLLECTOR_ID, 'planSha256': plan_sha,
                  'executionSha256': result['executionSha256'], 'requestBinding': copy.deepcopy(result_binding),
                  'terminalObservation': terminal, 'observedAt': _text(moments()), 'cleanupConfirmed': cleaned,
                  'pendingChildren': 0 if cleaned else 1,
                  'proofs': [copy.deepcopy(receipt['proof']) for receipt in receipts]}
        # The verifier, not the supervisor, decides; the result then states that decision.
        decided = verify(plan, execution, result, synthetic_collector_ledger=ledger, request_binding=binding)
        if decided['status'] not in _STATUSES:
            return result, ledger, 'supervisor-documents-invalid'
        if decided['status'] != result['status']:
            result.update(status=decided['status'], exitCode=decided['exitCode'])
            if verify(plan, execution, result, synthetic_collector_ledger=ledger,
                      request_binding=binding) != decided:
                return result, ledger, 'supervisor-verdict-unstable'
        return result, ledger, None

    result, ledger, problem = documents(terminal)
    # The claim must be live when the receipt is recorded. It is renewed here, after the
    # verification and with nothing written in between; a claim lost by now is unknown.
    if problem is None and terminal is not None and not supervisor._alive():
        terminal = None
        result, ledger, problem = documents(terminal)
    if problem is not None:
        # The verifier refused the supervisor's own documents: an unknown receipt without
        # checks or artifacts is recorded all the same, so the claim can be closed.
        result = dict(result, status='unknown', exitCode=_CODES['unknown'], checks=[],
                      missingCheckIds=[check['id'] for check in order], artifacts=[])
        ledger = dict(ledger, terminalObservation=None, proofs=[])
        shutil.rmtree(os.path.join(out, 'artifacts'), ignore_errors=True)
    recorded = ingest_receipt(journal, result)
    if recorded['status'] != 'recorded':
        return recorded if problem is None else _verdict('error', problem)
    observed = observe_completion(journal, plan, execution, result, synthetic_collector_ledger=ledger)
    if cleaned:
        closed = close(journal, request_id)
        if closed['status'] != 'closed' and observed['exitCode'] == 0 and problem is None:
            return closed
    # Written after the receipt: writing takes no time from the renewed claim.
    written = True
    try:
        _write(os.path.join(out, 'result.json'), cjson.dumps(result))
        _write(os.path.join(out, 'ledger.json'), cjson.dumps(ledger))
        _write(os.path.join(out, 'events.json'), cjson.dumps(events))
    except OSError:
        written = False  # the journal has the receipt; the verdict is then an error
    if problem is not None:
        return _verdict('error', problem)
    if not written:
        return _verdict('error', 'receipt-folder-unwritable')
    return observed
