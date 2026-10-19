"""Disposable WordPress only: real REST authentication and official adapter HTTP."""
import base64
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import time
import urllib.error
import urllib.request

ROOT = Path(os.environ['AFARA_WP_PATH'])
BASE = 'http://127.0.0.1:8080'
ROUTE = '/?rest_route=/afara/v1/mcp'
checks = 0


def check(condition, label):
    global checks
    if not condition:
        raise AssertionError(label)
    checks += 1
    print('PASS:', label)


def wp(*args):
    return subprocess.check_output(['wp', f'--path={ROOT}', *args], text=True).strip()


def request(message, auth=None, session=None, route=ROUTE, method='POST'):
    headers = {'Content-Type': 'application/json', 'Accept': 'application/json, text/event-stream'}
    if auth:
        headers['Authorization'] = 'Basic ' + base64.b64encode(auth.encode()).decode()
    if session:
        headers['Mcp-Session-Id'] = session
        headers['MCP-Protocol-Version'] = '2025-11-25'
    req = urllib.request.Request(BASE + route, data=json.dumps(message).encode() if method == 'POST' else None,
                                 headers=headers, method=method)
    try:
        response = urllib.request.urlopen(req, timeout=15)
    except urllib.error.HTTPError as error:
        response = error
    with response:
        raw = response.read()
        return response.status, dict(response.headers), json.loads(raw) if raw else None


def rpc(method, params=None):
    return {'jsonrpc': '2.0', 'id': 1, 'method': method, 'params': params if params is not None else {}}


def initialize(auth, route=ROUTE):
    status, headers, body = request(rpc('initialize', {
        'protocolVersion': '2025-11-25', 'capabilities': {},
        'clientInfo': {'name': 'afara-integration', 'version': '1.0'},
    }), auth, route=route)
    check(status == 200 and 'result' in body, 'authenticated MCP initialize')
    session = next((v for k, v in headers.items() if k.lower() == 'mcp-session-id'), None)
    check(bool(session), 'adapter returned legacy MCP session')
    status, _, _ = request({'jsonrpc': '2.0', 'method': 'notifications/initialized'}, auth, session, route)
    check(200 <= status < 300, 'initialized notification accepted')
    return session


def tool(auth, session, name, arguments):
    return request(rpc('tools/call', {'name': name, 'arguments': arguments}), auth, session)


def failed(body):
    return isinstance(body, dict) and ('error' in body or body.get('result', {}).get('isError') is True)


fixture = None
editor_id = None
admin_password_id = None
try:
    for attempt in range(30):
        try:
            request(rpc('initialize'))
            break
        except urllib.error.URLError:
            time.sleep(0.5)
    else:
        raise AssertionError('WordPress test server did not start')
    wp('option', 'delete', 'afara_enabled')
    wp('option', 'delete', 'afara_domain_lock')
    wp('option', 'delete', 'afara_activity_log')
    password = wp('user', 'application-password', 'create', 'admin', 'afara-http-test', '--porcelain')
    credentials = 'admin:' + password
    passwords = json.loads(wp('user', 'application-password', 'list', 'admin', '--format=json'))
    admin_password_id = next(p['uuid'] for p in passwords if p['name'] == 'afara-http-test')
    editor_id = wp('user', 'create', 'afara-http-editor', 'afara-editor@example.test', '--role=editor', '--porcelain')
    editor_password = wp('user', 'application-password', 'create', editor_id, 'afara-http-test', '--porcelain')
    check(request(rpc('tools/list'), credentials)[0] == 403, 'off by default with valid administrator credentials')
    wp('option', 'update', 'afara_enabled', '1')
    wp('option', 'update', 'afara_domain_lock', 'wrong.example.test')
    check(request(rpc('tools/list'), credentials)[0] == 403, 'domain mismatch denied')
    wp('option', 'update', 'afara_domain_lock', 'localhost')
    check(request(rpc('tools/list'))[0] == 401, 'anonymous denied')
    check(request(rpc('tools/list'), 'admin:invalid-application-password')[0] == 401, 'invalid credentials denied')
    check(request(rpc('tools/list'), 'afara-http-editor:' + editor_password)[0] == 403, 'authenticated editor denied')
    session = initialize(credentials)
    status, _, body = request(rpc('tools/list'), credentials, session)
    tools = body.get('result', {}).get('tools', [])
    expected = {'afara-site-context', 'afara-read-file', 'afara-list-directory'}
    check(status == 200 and {t['name'] for t in tools} == expected, 'exact three read-only tools discovered')
    check(all(t.get('annotations', {}).get('readOnlyHint') is True for t in tools), 'read-only annotations preserved')
    for method, key in [('resources/list', 'resources'), ('prompts/list', 'prompts')]:
        _, _, body = request(rpc(method), credentials, session)
        check(failed(body) or body.get('result', {}).get(key, []) == [], 'no extra ' + key)
    status, _, body = tool(credentials, session, 'afara-site-context', {})
    check(status == 200 and not failed(body) and 'wordpress_version' in json.dumps(body), 'site-context executes')
    fixture = Path(tempfile.mkdtemp(prefix='afara-mcp-', dir=ROOT / 'wp-content/themes'))
    relative = fixture.relative_to(ROOT).as_posix()
    (fixture / 'source.txt').write_text('afara-read-only-fixture\n')
    (fixture / 'config.php').write_text('sensitive-config-fixture')
    (fixture / '.env').write_text('hidden-fixture')
    (fixture / 'link.txt').symlink_to(fixture / 'source.txt')
    _, _, body = tool(credentials, session, 'afara-read-file', {'path': relative + '/source.txt'})
    check(not failed(body) and 'afara-read-only-fixture' in json.dumps(body), 'read-file reads permitted source')
    _, _, body = tool(credentials, session, 'afara-list-directory', {'path': relative})
    serialized = json.dumps(body)
    check(not failed(body) and 'source.txt' in serialized, 'list-directory lists permitted source')
    check(all(name not in serialized for name in ['config.php', '.env', 'link.txt']), 'listing hides sensitive and symlink entries')
    for path in [relative + '/config.php', relative + '/.env', relative + '/link.txt', '../wp-config.php', 'wp-config.php']:
        _, _, body = tool(credentials, session, 'afara-read-file', {'path': path})
        check(failed(body), 'unsafe source path denied: ' + path)
    _, _, body = tool(credentials, session, 'afara-read-file', {'path': relative + '/source.txt', 'limit': 20000})
    check(failed(body), 'ability input schema enforced')
    for name in ['afara-execute-php', 'afara-write-file', 'afara-delete-file']:
        _, _, body = tool(credentials, session, name, {})
        check(failed(body), 'unimplemented tool rejected: ' + name)
    check((fixture / 'source.txt').read_text() == 'afara-read-only-fixture\n', 'source unchanged')
    default_route = '/?rest_route=/mcp/mcp-adapter-default-server'
    default_session = initialize(credentials, default_route)
    _, _, body = request(rpc('tools/call', {'name': 'mcp-adapter-discover-abilities', 'arguments': {}}), credentials, default_session, default_route)
    check(not failed(body) and 'afara/' not in json.dumps(body), 'Afara excluded from default-server discovery')
    _, _, body = request(rpc('tools/call', {'name': 'mcp-adapter-execute-ability', 'arguments': {'ability_name': 'afara/site-context', 'parameters': {}}}), credentials, default_session, default_route)
    check(failed(body), 'default-server execution cannot reach private Afara abilities')
    check(request(None, credentials, session, method='GET')[0] == 405, 'GET/SSE unsupported')
    wp('option', 'update', 'afara_enabled', '0')
    check(request(rpc('tools/list'), credentials, session)[0] == 403, 'disable denies existing session discovery')
    check(tool(credentials, session, 'afara-site-context', {})[0] == 403, 'disable denies existing session execution')
    wp('option', 'update', 'afara_enabled', '1')
    wp('option', 'update', 'afara_domain_lock', 'moved.example.test')
    check(tool(credentials, session, 'afara-site-context', {})[0] == 403, 'domain change denies existing session execution')
    wp('option', 'update', 'afara_domain_lock', 'localhost')
    wp('user', 'application-password', 'delete', 'admin', admin_password_id)
    admin_password_id = None
    check(request(rpc('tools/list'), credentials, session)[0] == 401, 'revoked Application Password denied on existing session')

    log = json.loads(wp('option', 'get', 'afara_activity_log', '--format=json'))
    refused = [e for e in log if e['result'] == 'refused']
    reasons = [e['reason'] for e in refused]
    for reason in ['afara_disabled', 'afara_domain_mismatch', 'afara_not_signed_in', 'incorrect_password', 'afara_not_admin']:
        check(reason in reasons, 'activity log records refusal: ' + reason)
    check(reasons.count('incorrect_password') >= 1 and sum(e['count'] for e in refused if e['reason'] == 'incorrect_password') == 2,
          'invalid and revoked passwords both counted')
    editor = next(e for e in refused if e['reason'] == 'afara_not_admin')
    check(editor['user_login'] == 'afara-http-editor' and editor['connection'] == 'afara-http-test', 'refusal names the account and connection')
    ran = [e for e in log if e['result'] in ('success', 'error')]
    check(any(e['ability'] == 'afara/site-context' and e['result'] == 'success' and e['user_login'] == 'admin'
              and e['connection'] == 'afara-http-test' for e in ran), 'success names the account and connection')
    check(any(e['reason'] == 'afara_path_denied' for e in ran), 'denied path logged with reason')
    serialized_log = json.dumps(log)
    for secret in [password, editor_password, 'sensitive-config-fixture', 'hidden-fixture', 'wp-config', '127.0.0.1']:
        check(secret not in serialized_log, 'activity log stores no secrets, paths or IPs')
    check(all(sorted(e) == sorted(['time', 'user_id', 'user_login', 'connection', 'ability', 'result', 'reason', 'count']) for e in log),
          'activity log fields are exactly the documented set')
    print(f'::notice::{checks} WordPress HTTP integration checks passed')
finally:
    if fixture:
        shutil.rmtree(fixture)
    if admin_password_id:
        wp('user', 'application-password', 'delete', 'admin', admin_password_id)
    if editor_id:
        wp('user', 'delete', editor_id, '--yes')
    wp('option', 'delete', 'afara_enabled')
    wp('option', 'delete', 'afara_domain_lock')
    wp('option', 'delete', 'afara_activity_log')
