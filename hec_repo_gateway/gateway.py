"""Ingress-only constrained gateway. Only executes the explicitly approved fixed offline regression runner."""
import ast
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import threading
import urllib.request
import uuid
from http.server import BaseHTTPRequestHandler, HTTPServer
import safe_source as source

DATA = Path('/data')
LOCK = threading.Lock()
TOOLS = ['repo_status', 'repo_search', 'read_source', 'controlled_patch_source',
         'run_focused_tests', 'run_full_hec_regression', 'git_diff', 'git_diff_check',
         'git_stage_exact', 'git_commit_no_push', 'appdaemon_read', 'appdaemon_patch',
         'live_readback', 'fixture_create', 'snapshot_create']
OPTIONS = {'editable_paths': []}
PROTECTED = re.compile(r'goodwe|build\d+|tariff|taryf|secret|credential|token|password', re.I)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def audit(event, **fields):
    source.DATA = DATA
    source.audit(event, **fields)


def git(root, *args):
    # All callers use fixed command templates. No shell, source config, hooks or remotes.
    env = {'PATH': '/usr/bin:/bin', 'HOME': str(DATA), 'GIT_CONFIG_NOSYSTEM': '1',
           'GIT_CONFIG_GLOBAL': '/dev/null', 'GIT_TERMINAL_PROMPT': '0',
           'GIT_AUTHOR_NAME': 'HEC Gateway', 'GIT_AUTHOR_EMAIL': 'gateway@localhost',
           'GIT_COMMITTER_NAME': 'HEC Gateway', 'GIT_COMMITTER_EMAIL': 'gateway@localhost'}
    p = subprocess.run(['/usr/bin/git', '-c', 'core.hooksPath=/dev/null',
                        '-c', 'core.fsmonitor=false', *args], cwd=root, env=env,
                       capture_output=True, timeout=20)
    if len(p.stdout) + len(p.stderr) > 1024 * 1024:
        raise ValueError('Output limit')
    if p.returncode:
        raise ValueError('Git operation failed: ' + p.stderr.decode(errors='replace')[:200])
    return p.stdout.decode()


def workspace(session):
    if not isinstance(session, str) or not re.fullmatch('[a-f0-9]{32}', session):
        raise ValueError('Invalid isolated session')
    root = DATA / 'sessions' / session
    if not root.is_dir() or root.is_symlink():
        raise ValueError('Unknown session')
    return root


def exact(root, paths):
    manifest = json.loads((root / 'manifest.json').read_text())['files']
    if not isinstance(paths, list) or not paths or len(paths) > 20 or len(set(paths)) != len(paths):
        raise ValueError('1-20 unique exact paths required')
    for name in paths:
        if name not in manifest:
            raise ValueError('Path outside snapshot manifest')
        p = root / name
        if p.is_symlink() or not p.is_file() or p.stat().st_nlink != 1:
            raise ValueError('Unsafe snapshot file')
    return paths


def create(paths=None):
    session = uuid.uuid4().hex
    root = DATA / 'sessions' / session
    root.mkdir(parents=True, mode=0o700)
    if paths is None:
        files = {'fixture.py': b'VALUE = 1\n'}
        origins = {}
    else:
        if not isinstance(paths, list) or not 1 <= len(paths) <= 20 or len(set(paths)) != len(paths):
            raise ValueError('1-20 exact source paths required')
        files = {f'file_{i}{Path(p).suffix}': source.read_allowed(p) for i, p in enumerate(paths)}
        origins = {f'file_{i}{Path(p).suffix}': p for i, p in enumerate(paths)}
    for name, data in files.items():
        (root / name).write_bytes(data)
    (root / 'manifest.json').write_text(json.dumps({'files': list(files), 'origins': origins}))
    git(root, 'init', '--template=', '.')
    git(root, 'add', '--', *list(files))
    git(root, 'commit', '-m', 'Isolated baseline')
    audit('snapshot_created', session=session, files=list(files), origins=origins)
    return {'session': session, 'files': list(files), 'isolated': True}


def patch(a, appdaemon=False):
    old, new = a['old'], a['new']
    if not isinstance(old, str) or not old or not isinstance(new, str) or len(new.encode()) > source.MAX_BYTES:
        raise ValueError('Invalid replacement')
    if 'session' in a:
        root = workspace(a['session'])
        exact(root, [a['path']])
        p = root / a['path']
        before = p.read_bytes()
        parent_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        name = p.name
    else:
        p = Path(a['path'])
        if appdaemon and not str(p).startswith(source.ROOTS[1] + '/'):
            raise ValueError('Not AppDaemon')
        if str(p) not in OPTIONS['editable_paths'] or PROTECTED.search(str(p)):
            raise ValueError('Not on explicit editable path allowlist')
        before = source.read_allowed(str(p))
        # Content may legitimately mention protected device/tariff terms.
        # Safety is enforced by the exact editable-path allowlist and protected
        # path filter above; do not make an explicitly allowed source file
        # immutable merely because its code contains those words.
        # Walk from / with nofollow to retain a safe parent directory descriptor.
        parent_fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
        try:
            for part in p.parts[1:-1]:
                next_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent_fd)
                os.close(parent_fd)
                parent_fd = next_fd
        except Exception:
            os.close(parent_fd)
            raise
        name = p.name
    temporary = '.hec-patch-' + uuid.uuid4().hex
    try:
        if digest(before) != a['sha256'] or before.decode().count(old) != 1:
            raise ValueError('Hash mismatch or replacement not unique')
        after = before.decode().replace(old, new).encode()
        if len(after) > source.MAX_BYTES:
            raise ValueError('File too large')
        if p.suffix == '.py':
            ast.parse(after)
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent_fd)
        with os.fdopen(fd, 'rb') as s:
            info = os.fstat(s.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or s.read(source.MAX_BYTES+1) != before:
                raise ValueError('Source changed')
        audit('patch_requested', path=str(p), before=digest(before), after=digest(after))
        backup = DATA / 'backups' / (uuid.uuid4().hex + '.txt')
        backup.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        backup.write_bytes(before)
        backup.chmod(0o600)
        out = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, info.st_mode & 0o777, dir_fd=parent_fd)
        with os.fdopen(out, 'wb') as s:
            s.write(after)
            s.flush()
            os.fsync(s.fileno())
        os.rename(temporary, name, src_dir_fd=parent_fd, dst_dir_fd=parent_fd)
        os.fsync(parent_fd)
        audit('patch_completed', path=str(p), sha256=digest(after))
        return {'sha256': digest(after), 'isolated': 'session' in a}
    finally:
        try:
            os.unlink(temporary, dir_fd=parent_fd)
        except FileNotFoundError:
            pass
        os.close(parent_fd)


def health():
    mounts = []
    for root in source.ROOTS:
        try:
            fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                readonly = bool(os.fstatvfs(fd).f_flag & os.ST_RDONLY)
            finally:
                os.close(fd)
            mounts.append({'path': root, 'exists': True, 'writable_mount': not readonly})
        except OSError:
            mounts.append({'path': root, 'exists': False, 'writable_mount': False})
    return {'status': 'OK' if all(m['writable_mount'] for m in mounts) else 'BLOCKED',
            'mounts': mounts, 'goodwe_write': 0, 'tools': TOOLS,
            'git_scope': 'isolated snapshots only', 'editable_paths': OPTIONS['editable_paths']}


def scan(root, query=None):
    if root not in source.ROOTS:
        raise ValueError('Root not allowed')
    results = []
    checked = 0
    for folder, dirs, files in os.walk(root, followlinks=False):
        dirs[:] = [d for d in dirs if not d.startswith('.') and not PROTECTED.search(d) and not (Path(folder)/d).is_symlink()]
        for name in files:
            checked += 1
            if checked > 5000:
                return {'files': results, 'truncated': True}
            try:
                p = str(Path(folder)/name)
                content = source.read_allowed(p)
                if query is None or query in content.decode():
                    results.append({'path': p, 'sha256': digest(content), 'bytes': len(content)})
                    if len(results) >= 100:
                        return {'files': results, 'truncated': True}
            except (ValueError, OSError, UnicodeError):
                pass
    return {'files': results, 'truncated': False}


def call(tool, a):
    if tool not in TOOLS or not isinstance(a, dict):
        raise ValueError('Unknown tool')
    audit('operation', tool=tool)
    if tool == 'fixture_create':
        return create()
    if tool == 'snapshot_create':
        return create(a['paths'])
    if tool == 'repo_status':
        if 'session' in a:
            return {'status': git(workspace(a['session']), 'status', '--porcelain=v1'), 'isolated': True}
        return health()
    if tool == 'repo_search':
        q = a.get('query')
        if not isinstance(q, str) or not 1 <= len(q) <= 100:
            raise ValueError('Literal query required')
        return scan(a['root'], q)
    if tool in ('read_source', 'appdaemon_read'):
        if 'session' in a:
            root = workspace(a['session'])
            exact(root, [a['path']])
            data = (root / a['path']).read_bytes()
        else:
            if tool == 'appdaemon_read' and not a['path'].startswith(source.ROOTS[1]+'/'):
                raise ValueError('Not AppDaemon')
            data = source.read_allowed(a['path'])
        return {'content': data.decode(), 'sha256': digest(data)}
    if tool in ('controlled_patch_source', 'appdaemon_patch'):
        return patch(a, tool == 'appdaemon_patch')
    if tool == 'run_focused_tests':
        root = workspace(a['session'])
        paths = exact(root, a['paths'])
        for p in paths:
            if p.endswith('.py'):
                ast.parse((root/p).read_bytes())
        if 'fixture.py' in paths:
            tree = ast.parse((root/'fixture.py').read_bytes())
            if len(tree.body) != 1 or not isinstance(tree.body[0], ast.Assign) or not isinstance(tree.body[0].value, ast.Constant) or tree.body[0].value.value != a.get('expected_value', 2):
                raise ValueError('Fixture assertion failed')
        return {'status': 'PASS', 'suite': 'syntax and optional fixed fixture assertion', 'files': paths, 'executes_source': False}
    if tool == 'run_full_hec_regression':
        if a:
            raise ValueError('Full HEC regression accepts no arguments')
        # Literals are intentionally local: options, environment and request data
        # cannot replace the executable, arguments, cwd or timeout.
        command = ('/usr/local/bin/python', '-m', 'pytest', '-q', 'hec_audit_offline')
        cwd = '/homeassistant'
        # Historical HEC tests use this fixed scratch directory. It lives only
        # in the gateway app data volume and does not invoke or depend on OpenCode.
        regression_cache = DATA / 'v2' / 'cache' / 'opencode'
        regression_cache.mkdir(parents=True, exist_ok=True, mode=0o700)
        audit('full_hec_started', command=command, cwd=cwd, timeout=300)
        result = {'command': list(command), 'cwd': cwd, 'timeout_seconds': 300,
                  'exit_code': None, 'passed': None, 'failed': None}
        try:
            proc = subprocess.run(command, cwd=cwd, shell=False,
                                  capture_output=True, timeout=300,
                                  env={'PATH': '/usr/local/bin:/usr/bin:/bin', 'HOME': '/data',
                                       'PYTHONDONTWRITEBYTECODE': '1',
                                       'GOODWE_WRITE': '0'})
            result.update(exit_code=proc.returncode,
                          stdout=proc.stdout.decode(errors='replace'),
                          stderr=proc.stderr.decode(errors='replace'))
            # Only recognize the final anchored pytest summary, never arbitrary
            # occurrences of counts in test output.
            summary = re.search(r'^(?:=+ )?((?:\d+ [a-z]+(?:, )?)+) in \d+(?:\.\d+)?s(?: \(.*\))?(?: =+)?$',
                                result['stdout'].strip().split('\n')[-1])
            if summary:
                counts = dict((name, int(n)) for n, name in
                              re.findall(r'(\d+) ([a-z]+)', summary.group(1)))
                result.update(passed=counts.get('passed', 0),
                              failed=counts.get('failed', 0))
            result['status'] = ('PASS' if proc.returncode == 0 and summary
                                and result['failed'] == 0
                                and counts.get('passed', 0) > 0
                                and set(counts).issubset({'passed', 'skipped', 'xfailed', 'xpassed', 'warnings'})
                                else 'BLOCKED')
        except subprocess.TimeoutExpired as exc:
            result.update(status='BLOCKED', reason='Runner timed out',
                          stdout=(exc.stdout or b'').decode(errors='replace'),
                          stderr=(exc.stderr or b'').decode(errors='replace'))
        except OSError as exc:
            result.update(status='BLOCKED', reason='Runner could not start',
                          stdout='', stderr=str(exc))
        audit('full_hec_completed', **result)
        return result
    if tool in ('git_diff', 'git_diff_check', 'git_stage_exact', 'git_commit_no_push'):
        root = workspace(a['session'])
        paths = exact(root, a['paths'])
        if tool == 'git_diff':
            return {'diff': git(root, 'diff', 'HEAD', '--', *paths)}
        if tool == 'git_diff_check':
            git(root, 'diff', '--check', 'HEAD', '--', *paths)
            return {'status': 'PASS'}
        if tool == 'git_stage_exact':
            git(root, 'diff', '--check', 'HEAD', '--', *paths)
            git(root, 'reset', '--quiet', 'HEAD', '--', *json.loads((root/'manifest.json').read_text())['files'])
            git(root, 'add', '--', *paths)
            staged = git(root, 'diff', '--cached', '--name-only').splitlines()
            if set(staged) != set(paths):
                raise ValueError('Staged set differs from exact request')
            return {'staged': staged, 'isolated': True}
        staged = git(root, 'diff', '--cached', '--name-only').splitlines()
        if set(staged) != set(paths):
            raise ValueError('Staged set differs from exact request')
        git(root, 'diff', '--cached', '--check')
        git(root, 'diff', '--exit-code', '--', *paths)
        message = a.get('message', '')
        if not isinstance(message, str) or not 1 <= len(message) <= 200 or '\n' in message:
            raise ValueError('Invalid commit message')
        git(root, 'commit', '-m', message)
        commit = git(root, 'rev-parse', 'HEAD').strip()
        audit('commit_no_push', session=a['session'], commit=commit, paths=paths)
        return {'commit': commit, 'pushed': False, 'isolated': True}
    if tool == 'live_readback':
        # Only a fixed read-only HA endpoint; never services or GoodWe writes.
        token = os.environ.get('SUPERVISOR_TOKEN')
        if not token:
            raise ValueError('Supervisor token unavailable')
        request = urllib.request.Request('http://supervisor/core/api/states/sensor.hec_runtime',
                                         headers={'Authorization': 'Bearer '+token})
        with urllib.request.urlopen(request, timeout=15) as response:
            data = response.read(1024*1024+1)
        if len(data) > 1024*1024:
            raise ValueError('Readback limit')
        return json.loads(data)
    raise ValueError('Unsupported operation')


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass
    def allowed(self):
        return self.client_address[0] == '172.30.32.2'
    def reply(self, code, payload):
        data = json.dumps(payload).encode()
        self.send_response(code)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(data)))
        self.end_headers()
        self.wfile.write(data)
    def do_GET(self):
        if not self.allowed():
            return self.reply(403, {'error': 'Ingress only'})
        if self.path in ('/', '/health'):
            return self.reply(200, health())
        if self.path == '/tools':
            return self.reply(200, {'tools': TOOLS, 'documentation': 'DOCS.md in repository'})
        return self.reply(404, {'error': 'Unknown endpoint'})
    def do_POST(self):
        if not self.allowed():
            return self.reply(403, {'error': 'Ingress only'})
        with LOCK:
            try:
                self.connection.settimeout(15)
                length = int(self.headers.get('Content-Length', '0'))
                if self.path != '/call' or not 0 < length <= 65536:
                    raise ValueError('Invalid request')
                p = json.loads(self.rfile.read(length))
                result = call(p['tool'], p.get('arguments', {}))
                self.reply(200, result)
            except Exception as e:
                audit('denied', reason=type(e).__name__)
                self.reply(400, {'error': str(e)[:200]})


def main():
    global OPTIONS
    OPTIONS = json.loads((DATA/'options.json').read_text())
    if not isinstance(OPTIONS.get('editable_paths'), list):
        raise SystemExit('Invalid editable_paths')
    if os.environ.get('GOODWE_WRITE', '0') != '0':
        raise SystemExit('GOODWE_WRITE must be 0')
    audit('startup', goodwe_write=0)
    print(json.dumps(health()), flush=True)
    HTTPServer(('0.0.0.0', 8099), Handler).serve_forever()


if __name__ == '__main__':
    main()
