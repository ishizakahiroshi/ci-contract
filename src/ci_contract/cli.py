"""Byte, selection, planning, verification and local execution CLI.

Diagnostics never interpolate input values or filenames; execute adds only the
engine's fixed reason code.
"""
import argparse
import os
import sys
from pathlib import Path
from . import cjson
from .arrays import normalize
from .hashing import domain_hash, raw_hash, canonical_hash
from .errors import InputError, BlockedError, OK, INVALID_INPUT, BLOCKED, INTERNAL_ERROR


def _declared_paths(value):
    """Literal paths an explain input declares, split by when select checks them.

    Returns (root, model): changedPaths / changes are checked before scope
    admission; ownership and path-instance rules of model / baseModel only after
    it. The input already passed select's shape checks, so this only reads it.
    """
    root = []
    if isinstance(value.get('changedPaths'), list):
        root.extend(p for p in value['changedPaths'] if isinstance(p, str))
    for change in value.get('changes', []) if isinstance(value.get('changes'), list) else []:
        if isinstance(change, dict):
            root.extend(change[k] for k in ('path', 'old', 'new') if isinstance(change.get(k), str))
    model = []
    for name in ('model', 'baseModel'):
        declared = value.get(name)
        if isinstance(declared, dict):
            for field in ('literalInputOwners', 'pathInstanceIds'):
                if isinstance(declared.get(field), dict):
                    model.extend(declared[field])
    return root, model


# select returns these before it validates model / baseModel, so their paths
# are not checked for them either (a malformed unused model stays blocked / 4).
_BEFORE_MODEL = frozenset(('excluded-scope', 'unknown-scope-alias',
                           'scope-registry-conflict', 'unknown-repository-group'))


def _explain(value):
    """select(), with every path held to the inventory's path rule.

    selection.select checks a weaker path grammar (no .git alias, length limit or
    conin$ / conout$ rule). The same literal paths name files in the source
    inventory, so explain refuses what inventory.validate_paths refuses.
    """
    from .inventory import validate_paths
    from .selection import select, _result
    result = select(value)
    if result['exitCode'] == 3:
        return result
    root, model = _declared_paths(value)
    if result['reasonCode'] not in _BEFORE_MODEL:
        root = root + model
    try:
        validate_paths(sorted(set(root)))
    except InputError:
        return _result('invalid-input', 3, 'invalid-selection-input')
    return result


class _Parser(argparse.ArgumentParser):
    def error(self, message):
        raise InputError("invalid command arguments")


def _parser():
    parser = _Parser(prog='ci-contract', description='Byte operations and M2 selection explanation', add_help=False)
    commands = parser.add_subparsers(dest='command', required=True, parser_class=_Parser)
    canon = commands.add_parser('canon', add_help=False)
    canon.add_argument('file', nargs='?', default='-')
    canon.add_argument('--kind')
    hashing = commands.add_parser('hash', add_help=False)
    hashing.add_argument('file', nargs='?', default='-')
    mode = hashing.add_mutually_exclusive_group(required=True)
    mode.add_argument('--domain')
    mode.add_argument('--raw', action='store_true')
    mode.add_argument('--canonical', action='store_true')
    hashing.add_argument('--kind')
    validation = commands.add_parser('validate', add_help=False)
    validation.add_argument('file', nargs='?', default='-')
    explain = commands.add_parser('explain', add_help=False)
    explain.add_argument('file', nargs='?', default='-')
    plan = commands.add_parser('plan', add_help=False)
    plan.add_argument('--repo', required=True)
    plan.add_argument('--repo-path', required=True)
    selection = plan.add_mutually_exclusive_group(required=True)
    selection.add_argument('--base')
    selection.add_argument('--selection')
    plan.add_argument('--target')
    plan.add_argument('--snapshot')
    plan.add_argument('--include', action='append', default=[])
    plan.add_argument('--profile', required=True, choices=['change','case','integration','release','operations'])
    plan.add_argument('--out', required=True)
    verify = commands.add_parser('verify', add_help=False)
    verify.add_argument('--plan', required=True)
    verify.add_argument('--execution', required=True)
    verify.add_argument('--result', required=True)
    execute = commands.add_parser('execute', add_help=False)
    execute.add_argument('--plan', required=True)
    execute.add_argument('--target', required=True, choices=['local', 'github'])
    execute.add_argument('--out', required=True)
    execute.add_argument('--repo-path', required=True)
    execute.add_argument('--snapshot')
    execute.add_argument('--host', required=True)
    execute.add_argument('--journal', required=True)
    execute.add_argument('--anchor', required=True)
    execute.add_argument('--authority-id', required=True)
    execute.add_argument('--new-journal', action='store_true')
    execute.add_argument('--request-id')
    return parser


def _execute(args):
    """execute --target local: the final verdict's status on stdout, its fixed reason on stderr."""
    from datetime import datetime, timezone
    from .execute import check_inputs, execute
    from .journal import AuthorityUnknown, LocalJournal
    from .request import StaleError
    try:
        try:
            plan = cjson.loads(Path(args.plan).read_bytes())
            host = cjson.loads(Path(args.host).read_bytes())
        except OSError:
            raise InputError('input unavailable') from None
        check_inputs(plan, host)  # shapes (3) precede every refusal, --target github included
        if args.target != 'local':
            raise BlockedError('execute-target-unsupported')
        repo = os.path.abspath(args.repo_path)
        snapshot = None if args.snapshot is None else os.path.abspath(args.snapshot)
        roots = [repo] if snapshot is None else [repo, snapshot]
        opener = LocalJournal.create if args.new_journal else LocalJournal

        def journal():
            # Called by execute at step 4 only: a refusal before it creates no journal.
            return opener(os.path.abspath(args.journal), authority_id=args.authority_id, repository_roots=roots,
                          anchor_path=os.path.abspath(args.anchor))
        verdict = execute(plan, target=args.target, out=os.path.abspath(args.out), repo_path=repo, host=host,
                          journal_factory=journal, clock=lambda: datetime.now(timezone.utc), snapshot_dir=snapshot,
                          request_id=args.request_id)
    except InputError:
        verdict = {'status': 'invalid-input', 'exitCode': 3}
    except StaleError as error:
        verdict = {'status': 'stale', 'exitCode': 5, 'reasonCode': error.reason_code}
    except BlockedError as error:
        verdict = {'status': 'blocked', 'exitCode': 4, 'reasonCode': error.reason_code}
    except AuthorityUnknown as error:
        verdict = {'status': 'unknown', 'exitCode': 8, 'reasonCode': error.reason_code}
    except OSError:
        verdict = {'status': 'error', 'exitCode': INTERNAL_ERROR, 'reasonCode': 'local-io-failed'}
    except Exception:
        # Every outcome prints its status; the reason never carries an exception's text.
        verdict = {'status': 'error', 'exitCode': INTERNAL_ERROR, 'reasonCode': 'internal-error'}
    sys.stdout.buffer.write(verdict['status'].encode('ascii') + b'\n')
    if verdict['exitCode']:
        # Reason codes are fixed identifiers of the engine, never input values.
        reason = verdict.get('reasonCode')
        line = 'ci-contract: ' + verdict['status'] + ('' if reason is None else ': ' + reason) + '\n'
        sys.stderr.buffer.write(line.encode('ascii'))
    return verdict['exitCode']


def main(argv=None):
    command_args = sys.argv[1:] if argv is None else argv
    verifying = bool(command_args and command_args[0] == 'verify')
    try:
        args = _parser().parse_args(argv)
        exit_code = OK
        if args.command == 'execute':
            return _execute(args)
        if args.command == 'verify':
            from .verify import verify
            try:
                documents = [cjson.loads(Path(name).read_bytes()) for name in
                             (args.plan, args.execution, args.result)]
                verdict = verify(*documents)
            except (OSError, InputError):
                verdict = {'status': 'invalid-input', 'exitCode': INVALID_INPUT}
            except Exception:
                verdict = {'status': 'error', 'exitCode': INTERNAL_ERROR}
            sys.stdout.buffer.write(verdict['status'].encode('ascii') + b'\n')
            if verdict['exitCode']:
                diagnostic = (b'ci-contract: invalid input\n' if verdict['exitCode'] == INVALID_INPUT else
                              b'ci-contract: internal error\n' if verdict['exitCode'] == INTERNAL_ERROR else
                              b'ci-contract: verification not accepted\n')
                sys.stderr.buffer.write(diagnostic)
            return verdict['exitCode']
        if args.command == 'plan':
            from .plan import build_plan, plan_bytes, plan_digest
            # Exactly one target side: a commit (--target) or a snapshot directory (--snapshot, with --base).
            if (args.target is None) == (args.snapshot is None):
                raise InputError('invalid command arguments')
            if args.snapshot is None and args.include:
                raise InputError('invalid command arguments')
            if args.snapshot is not None:
                if args.selection is not None:
                    raise InputError('invalid command arguments')
                value = build_plan(args.repo_path, args.repo, args.base, None, args.profile,
                                   snapshot_dir=os.path.abspath(args.snapshot), include=args.include)
            elif args.selection is not None:
                from .request import build_request_from_git
                try:
                    selection_bytes = Path(args.selection).read_bytes()
                except OSError:
                    raise InputError('selection unavailable') from None
                value = build_request_from_git(args.repo_path, args.repo,
                                               selection_bytes, args.target, args.profile)
            else:
                value = build_plan(args.repo_path, args.repo, args.base, args.target, args.profile)
            data = plan_bytes(value)
            digest = plan_digest(value)
            created = False
            try:
                # Exclusive binary creation: existing files/symlinks are never
                # truncated. No partial planning result is written on failure.
                with Path(args.out).open('xb') as output:
                    created = True
                    if output.write(data) != len(data):
                        raise OSError('incomplete output')
            except OSError:
                if created:
                    # Only this invocation's new incomplete artifact is removed.
                    # A preexisting file (including a symlink) is untouched.
                    try:
                        Path(args.out).unlink(missing_ok=True)
                    except OSError:
                        raise RuntimeError('incomplete output cleanup failed') from None
                raise InputError('output unavailable') from None
            try:
                receipt = digest.encode('ascii') + b'\n'
                if sys.stdout.buffer.write(receipt) != len(receipt):
                    raise OSError('incomplete digest output')
                sys.stdout.buffer.flush()
            except Exception:
                # A successful file without its successful CLI receipt must not
                # survive a failed invocation. This path owns the exclusive file.
                try:
                    Path(args.out).unlink(missing_ok=True)
                except OSError:
                    raise RuntimeError('output cleanup failed') from None
                raise RuntimeError('digest output unavailable') from None
            return OK
        if args.command == 'hash' and args.kind is not None and not args.canonical:
            raise InputError("kind only applies to canonical raw hash")
        try:
            data = sys.stdin.buffer.read() if args.file == '-' else Path(args.file).read_bytes()
        except OSError:
            raise InputError("input unavailable") from None
        if args.command == 'hash' and args.raw:
            output = raw_hash(data).encode('ascii') + b'\n'
        else:
            value = cjson.loads(data)
            if args.command == 'explain':
                result = _explain(value)
                output = cjson.dumps(result)
                exit_code = result['exitCode']
            elif args.command == 'canon':
                output = cjson.dumps(normalize(value, args.kind))
            elif args.command == 'hash':
                digest = domain_hash(args.domain, value) if args.domain else canonical_hash(value, args.kind)
                output = digest.encode('ascii') + b'\n'
            else:
                from .schema import validate
                validate(value)
                output = b''
        sys.stdout.buffer.write(output)
        return exit_code
    except BlockedError as error:
        from .request import StaleError
        if isinstance(error, StaleError):
            sys.stderr.buffer.write(b'ci-contract: stale\n')
            return 5
        sys.stderr.buffer.write(b'ci-contract: blocked\n')
        return BLOCKED
    except InputError:
        if verifying:
            sys.stdout.buffer.write(b'invalid-input\n')
        sys.stderr.buffer.write(b'ci-contract: invalid input\n')
        return INVALID_INPUT
    except Exception:
        sys.stderr.buffer.write(b'ci-contract: internal error\n')
        return INTERNAL_ERROR
