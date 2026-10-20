"""Read-only byte and selection CLI; diagnostics never interpolate input values or filenames."""
import argparse
import sys
from pathlib import Path
from . import cjson
from .arrays import normalize
from .hashing import domain_hash, raw_hash, canonical_hash
from .errors import InputError, BlockedError, OK, INVALID_INPUT, BLOCKED, INTERNAL_ERROR


class _Parser(argparse.ArgumentParser):
    def error(self, message):
        raise InputError("invalid command arguments")


def _parser():
    parser = _Parser(prog='ci-contract', description='Byte operations and M2 selection explanation')
    commands = parser.add_subparsers(dest='command', required=True, parser_class=_Parser)
    canon = commands.add_parser('canon')
    canon.add_argument('file', nargs='?', default='-')
    canon.add_argument('--kind')
    hashing = commands.add_parser('hash')
    hashing.add_argument('file', nargs='?', default='-')
    mode = hashing.add_mutually_exclusive_group(required=True)
    mode.add_argument('--domain')
    mode.add_argument('--raw', action='store_true')
    mode.add_argument('--canonical', action='store_true')
    hashing.add_argument('--kind')
    validation = commands.add_parser('validate')
    validation.add_argument('file', nargs='?', default='-')
    explain = commands.add_parser('explain')
    explain.add_argument('file', nargs='?', default='-')
    plan = commands.add_parser('plan')
    plan.add_argument('--repo', required=True)
    plan.add_argument('--repo-path', required=True)
    plan.add_argument('--base', required=True)
    plan.add_argument('--target', required=True)
    plan.add_argument('--profile', required=True, choices=['change'])
    plan.add_argument('--out', required=True)
    return parser


def main(argv=None):
    try:
        args = _parser().parse_args(argv)
        exit_code = OK
        if args.command == 'plan':
            from .plan import build_plan, plan_bytes, plan_digest
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
                from .selection import select
                result = select(value)
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
    except BlockedError:
        sys.stderr.buffer.write(b'ci-contract: blocked\n')
        return BLOCKED
    except InputError:
        sys.stderr.buffer.write(b'ci-contract: invalid input\n')
        return INVALID_INPUT
    except Exception:
        sys.stderr.buffer.write(b'ci-contract: internal error\n')
        return INTERNAL_ERROR
