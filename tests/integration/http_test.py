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
import urllib.parse
import urllib.request

ROOT = Path(os.environ['AFARA_WP_PATH'])
BASE = 'http://127.0.0.1:8080'
ROUTE = '/?rest_route=/afara/v1/mcp'
checks = 0


last_pass = '(none)'


def check(condition, label):
    global checks, last_pass
    if not condition:
        raise AssertionError(label)
    checks += 1
    last_pass = label
    print('PASS:', label)


def annotate(error):
    # CI logs aren't always readable remotely; annotations are.
    message = f'{type(error).__name__}: {error} | last passing check: {last_pass}'.replace('%', '%25').replace('\n', '%0A')
    print(f'::error title=Integration check failed::{message}')
    try:
        for line in Path('/tmp/afara-http.log').read_text(errors='replace').splitlines()[-200:]:
            if 'PHP' in line and ('Fatal' in line or 'Warning' in line or 'Error' in line or 'Deprecated' in line):
                print('::error title=PHP::' + line[-900:].replace('%', '%25'))
    except OSError:
        pass


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
ep = None
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
    admin_uuid = admin_password_id
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
    expected = {'afara-site-context', 'afara-read-file', 'afara-list-directory', 'afara-elementor-document', 'afara-elementor-update-text', 'afara-elementor-update-image'}
    check(status == 200 and {t['name'] for t in tools} == expected, 'exact Afara tool allowlist discovered')
    check(all(t.get('annotations', {}).get('readOnlyHint') is (t['name'] not in {'afara-elementor-update-text', 'afara-elementor-update-image'}) for t in tools), 'read-only annotations preserved')
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
    # Elementor: real Document API, guarded writes, revision backups, stale hashes.
    ep = json.loads(subprocess.check_output(['wp', f'--path={ROOT}', '--user=admin', 'eval-file', str(Path(__file__).with_name('elementor_fixture.php').resolve())], text=True))
    eid = ep['post_id']

    def elementor_result(body):
        result = body.get('result', {})
        if 'structuredContent' in result:
            return result['structuredContent']
        return json.loads(result['content'][0]['text'])

    def read_elementor():
        status, _, body = tool(credentials, session, 'afara-elementor-document', {'post_id': eid})
        check(status == 200 and not failed(body), 'elementor: document read')
        return elementor_result(body)

    doc = read_elementor()
    edit_args = {'post_id': eid, 'element_id': 'abcdef1', 'expected_sha256': doc['sha256'], 'text': 'Agent heading'}
    _, _, body = tool(credentials, session, 'afara-elementor-update-text', edit_args)
    check(failed(body), 'elementor: read-only default denies writes')
    wp('option', 'update', 'afara_read_only', '0')
    _, _, body = tool(credentials, session, 'afara-elementor-update-text', edit_args)
    check(failed(body), 'elementor: safe mode default denies writes')
    wp('option', 'update', 'afara_sandbox_safe_mode', '0')
    _, _, body = tool(credentials, session, 'afara-elementor-update-text', edit_args)
    check(not failed(body), 'elementor: allowed text edit through real adapter')
    edit_response = elementor_result(body)
    check(edit_response['revision_id'] > 0, 'elementor: revision backup ID returned')
    backup = wp('post', 'meta', 'get', str(edit_response['revision_id']), '_elementor_data')
    check('Original heading' in backup and 'Agent heading' not in backup, 'elementor: backup contains exact pre-edit content')
    after = read_elementor()
    children = after['elements'][0]['elements']
    check(children[0]['settings']['title'] == 'Agent heading' and children[0]['settings']['align'] == 'center'
          and children[2]['settings']['text'] == 'Original button', 'elementor: targeted text only, sibling/settings preserved')
    _, _, body = tool(credentials, session, 'afara-elementor-update-text', edit_args)
    check(failed(body), 'elementor: stale checksum refused')
    _, _, body = tool(credentials, session, 'afara-elementor-update-text', {**edit_args, 'expected_sha256': after['sha256'], 'text': '[unsafe_shortcode]'})
    check(failed(body), 'elementor: shortcodes refused')
    _, _, body = tool(credentials, session, 'afara-elementor-update-image', {'post_id': eid, 'element_id': 'abcdef2', 'expected_sha256': after['sha256'], 'attachment_id': ep['attachment_id']})
    check(not failed(body), 'elementor: existing image widget updated from media library')
    after = read_elementor()
    check(after['elements'][0]['elements'][1]['settings']['image']['id'] == ep['attachment_id'], 'elementor: image edit persisted')
    wp('post', 'update', str(eid), '--post_status=publish')
    _, _, body = tool(credentials, session, 'afara-elementor-update-text', {**edit_args, 'expected_sha256': after['sha256']})
    check(failed(body), 'elementor: published pages cannot be changed')
    wp('post', 'update', str(eid), '--post_status=draft')
    wp('option', 'update', 'afara_read_only', '1')
    wp('option', 'update', 'afara_sandbox_safe_mode', '1')

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
    listing = json.loads(subprocess.check_output(['wp', f'--path={ROOT}', '--user=admin', 'eval',
                                                  'echo wp_json_encode(\\Afara\\Admin\\Connections::all());'], text=True))
    mine = next((c for c in listing if c['uuid'] == admin_password_id), None)
    check(mine is not None and mine['name'] == 'afara-http-test' and mine['can_revoke'], 'Connections lists the admin Application Password')
    check(mine['afara'] is not None and mine['afara']['connection_id'] == admin_password_id, 'Connections links Afara activity by ID')
    check(all(c['user_login'] != 'afara-http-editor' for c in listing), 'Connections excludes non-administrators')
    check(all('password' not in c for c in listing) and '$wp$' not in json.dumps(listing) and '$P$' not in json.dumps(listing),
          'Connections exposes no password hashes')
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
              and e['connection'] == 'afara-http-test' and e['connection_id'] == admin_uuid for e in ran), 'success names the account and connection')
    check(any(e['reason'] == 'afara_path_denied' for e in ran), 'denied path logged with reason')
    serialized_log = json.dumps(log)
    for secret in [password, editor_password, 'sensitive-config-fixture', 'hidden-fixture', 'wp-config', '127.0.0.1']:
        check(secret not in serialized_log, 'activity log stores no secrets, paths or IPs')
    check(all(sorted(e) == sorted(['time', 'user_id', 'user_login', 'connection', 'connection_id', 'ability', 'result', 'reason', 'count']) for e in log),
          'activity log fields are exactly the documented set')

    # Quiet mode: hides Afara from unlisted admins, never blocks them.
    client_id = wp('user', 'create', 'afara-http-client', 'afara-client@example.test', '--role=administrator', '--porcelain')
    admin_id = wp('user', 'get', 'admin', '--field=ID')
    wp('option', 'update', 'afara_quiet_mode', '1')
    wp('option', 'update', 'afara_quiet_users', json.dumps([int(admin_id)]), '--format=json')
    probe = ('require_once ABSPATH . "wp-admin/includes/plugin.php"; $p = apply_filters("all_plugins", get_plugins());'
             'echo wp_json_encode(["row" => (bool) array_filter(array_keys($p), fn($k) => str_starts_with($k, "afara/")),'
             '"visible" => \\Afara\\Admin\\QuietMode::visibleToCurrentUser()]);')
    as_user = lambda user, code: json.loads(subprocess.check_output(['wp', f'--path={ROOT}', f'--user={user}', 'eval', code], text=True))
    seen = as_user('admin', probe)
    check(seen['row'] and seen['visible'], 'quiet mode: listed admin still sees Afara')
    seen = as_user('afara-http-client', probe)
    check(not seen['row'] and not seen['visible'], 'quiet mode: unlisted admin does not see Afara on Plugins')
    seen = as_user('afara-http-client', 'define("AFARA_QUIET_MODE_OFF", true);' + probe)
    check(seen['row'] and seen['visible'], 'quiet mode: wp-config constant shows Afara again')
    client_password = wp('user', 'application-password', 'create', client_id, 'afara-quiet-test', '--porcelain')
    client_session = initialize('afara-http-client:' + client_password)
    status, _, body = request(rpc('tools/list'), 'afara-http-client:' + client_password, client_session)
    check(status == 200 and len(body.get('result', {}).get('tools', [])) == 3, 'quiet mode hides, never blocks: hidden admin can still connect')
    wp('user', 'delete', client_id, '--yes')
    wp('option', 'delete', 'afara_quiet_mode')
    wp('option', 'delete', 'afara_quiet_users')

    # OAuth 2.1: discovery from the 401, registration, consent, PKCE, tokens, refresh, revoke.
    wp('rewrite', 'structure', '/%postname%/')
    wp('option', 'update', 'afara_oauth_enabled', '1')
    pretty = '/wp-json/afara/v1/mcp'

    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *args, **kwargs):
            return None  # Report 3xx as-is; WordPress may redirect to its https://localhost canonical URL.

    no_redirect = urllib.request.build_opener(NoRedirect)

    def raw(path, data=None, headers=None, method=None):
        req = urllib.request.Request(BASE + path, data=data, headers=headers or {}, method=method or ('POST' if data is not None else 'GET'))
        try:
            response = no_redirect.open(req, timeout=15)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            body = response.read()
            return response.status, {k.lower(): v for k, v in response.headers.items()}, body

    def mcp_bearer(message, token, session=None, path=pretty):
        headers = {'Content-Type': 'application/json', 'Accept': 'application/json, text/event-stream', 'Authorization': 'Bearer ' + token}
        if session:
            headers['Mcp-Session-Id'] = session
            headers['MCP-Protocol-Version'] = '2025-11-25'
        status, h, body = raw(path, json.dumps(message).encode(), headers)
        return status, h, json.loads(body) if body else None

    def form(path, fields):
        status, h, body = raw(path, urllib.parse.urlencode(fields).encode(), {'Content-Type': 'application/x-www-form-urlencoded'})
        return status, h, json.loads(body) if body else None

    def local(url):
        parts = urllib.parse.urlsplit(url)
        return parts.path + ('?' + parts.query if parts.query else '')

    status, h, _ = raw(pretty, json.dumps(rpc('tools/list')).encode(), {'Content-Type': 'application/json'})
    challenge = h.get('www-authenticate', '')
    check(status == 401 and challenge.startswith('Bearer ') and 'resource_metadata="' in challenge and 'scope="afara:read"' in challenge,
          'oauth: 401 carries a Bearer challenge with resource_metadata and scope')
    prm_url = challenge.split('resource_metadata="')[1].split('"')[0]
    check('/.well-known/oauth-protected-resource/wp-json/afara/v1/mcp' in prm_url, 'oauth: resource metadata at the RFC 9728 path-inserted URL')
    status, _, body = raw(local(prm_url))
    prm = json.loads(body)
    check(status == 200 and prm['resource'].endswith('/wp-json/afara/v1/mcp') and prm['authorization_servers'], 'oauth: protected resource metadata served')
    issuer = prm['authorization_servers'][0]
    issuer_path = urllib.parse.urlsplit(issuer).path
    status, _, body = raw('/.well-known/oauth-authorization-server' + issuer_path)
    asm = json.loads(body)
    check(status == 200 and asm['issuer'] == issuer and asm['code_challenge_methods_supported'] == ['S256'], 'oauth: authorization server metadata (RFC 8414 path insertion)')
    status, _, body = raw('/.well-known/openid-configuration' + issuer_path)
    check(status == 200 and json.loads(body)['issuer'] == issuer, 'oauth: OpenID-style discovery fallback')

    redirect = 'http://127.0.0.1:33418/callback'
    status, _, body = raw(local(asm['registration_endpoint']), json.dumps({'client_name': 'Afara CI', 'redirect_uris': [redirect]}).encode(),
                          {'Content-Type': 'application/json'})
    client = json.loads(body)
    check(status == 201 and client['client_id'].startswith('afara-'), 'oauth: dynamic client registration')
    status, _, body = raw(local(asm['registration_endpoint']), json.dumps({'redirect_uris': ['http://evil.example/cb']}).encode(), {'Content-Type': 'application/json'})
    check(status == 400, 'oauth: non-HTTPS, non-loopback redirect refused at registration')

    def authorize(verifier):
        import hashlib
        challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip('=')
        query = {'response_type': 'code', 'client_id': client['client_id'], 'redirect_uri': redirect, 'code_challenge': challenge,
                 'code_challenge_method': 'S256', 'state': 'ci-state', 'scope': 'afara:read', 'resource': prm['resource']}
        code = ("$c = \\Afara\\OAuth\\AuthorizationServer::checkAuthorizeRequest(json_decode('" + json.dumps(query) + "', true));"
                "echo $c['ok'] ? \\Afara\\OAuth\\AuthorizationServer::approve($c['params'], get_current_user_id()) : 'ERR:' . $c['message'];")
        url = subprocess.check_output(['wp', f'--path={ROOT}', '--user=admin', 'eval', code], text=True).strip()
        check(url.startswith(redirect + '?code='), 'oauth: consent approval returns a code to the registered redirect')
        returned = dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(url).query))
        check(returned.get('state') == 'ci-state' and returned.get('iss') == issuer, 'oauth: redirect carries state and iss')
        return returned['code']

    def exchange(code, verifier):
        return form(local(asm['token_endpoint']), {'grant_type': 'authorization_code', 'client_id': client['client_id'], 'code': code,
                                                    'redirect_uri': redirect, 'code_verifier': verifier, 'resource': prm['resource']})

    verifier = base64.urlsafe_b64encode(os.urandom(40)).decode().rstrip('=')
    code = authorize(verifier)
    status, h, body = exchange(code, 'x' * 50)
    check(status == 400 and body['error'] == 'invalid_grant', 'oauth: wrong PKCE verifier refused')
    code = authorize(verifier)
    status, h, tokens = exchange(code, verifier)
    check(status == 200 and tokens['token_type'] == 'Bearer' and tokens['expires_in'] == 3600 and h.get('cache-control') == 'no-store',
          'oauth: code exchanged for tokens (no-store)')
    status, h, body = mcp_bearer(rpc('initialize', {'protocolVersion': '2025-11-25', 'capabilities': {}, 'clientInfo': {'name': 'afara-oauth-ci', 'version': '1'}}),
                                 tokens['access_token'])
    oauth_session = h.get('mcp-session-id')
    check(status == 200 and oauth_session, 'oauth: MCP initialize with a bearer token')
    mcp_bearer({'jsonrpc': '2.0', 'method': 'notifications/initialized'}, tokens['access_token'], oauth_session)
    status, _, body = mcp_bearer(rpc('tools/list'), tokens['access_token'], oauth_session)
    check(status == 200 and {t['name'] for t in body['result']['tools']} == expected, 'oauth: bearer token lists the same Afara tools')
    status, _, body = mcp_bearer(rpc('tools/call', {'name': 'afara-site-context', 'arguments': {}}), tokens['access_token'], oauth_session)
    check(status == 200 and not failed(body), 'oauth: bearer token runs site-context')
    wp('option', 'update', 'afara_read_only', '0')
    wp('option', 'update', 'afara_sandbox_safe_mode', '0')
    fresh = wp('post', 'meta', 'get', str(eid), '_elementor_data')
    status, _, body = mcp_bearer(rpc('tools/call', {'name': 'afara-elementor-update-text', 'arguments': {**edit_args, 'expected_sha256': read_elementor()['sha256']}}), tokens['access_token'], oauth_session)
    check(failed(body) and wp('post', 'meta', 'get', str(eid), '_elementor_data') == fresh, 'oauth: read scope cannot write even with all admin write switches enabled')
    wp('option', 'update', 'afara_read_only', '1')
    wp('option', 'update', 'afara_sandbox_safe_mode', '1')
    status, _, _ = raw('/wp-json/wp/v2/users/me', headers={'Authorization': 'Bearer ' + tokens['access_token']})
    check(status == 401, 'oauth: Afara tokens sign nobody in on other WordPress routes')
    status, h, _ = mcp_bearer(rpc('tools/list'), 'forged-token', oauth_session)
    check(status == 401 and 'error="invalid_token"' in h.get('www-authenticate', ''), 'oauth: forged token gets 401 invalid_token')
    status, _, _ = exchange(code, verifier)
    check(status == 400, 'oauth: authorization code is single-use')
    status, _, _ = mcp_bearer(rpc('tools/list'), tokens['access_token'], oauth_session)
    check(status == 401, 'oauth: replaying a code revokes the tokens it produced')

    code = authorize(verifier)
    _, _, tokens = exchange(code, verifier)
    status, _, rotated = form(local(asm['token_endpoint']), {'grant_type': 'refresh_token', 'client_id': client['client_id'], 'refresh_token': tokens['refresh_token']})
    check(status == 200 and rotated['refresh_token'] != tokens['refresh_token'], 'oauth: refresh rotates the refresh token')
    status, _, _ = mcp_bearer(rpc('tools/list'), rotated['access_token'], oauth_session)
    check(status == 200, 'oauth: refreshed access token works')
    status, _, body = form(local(asm['token_endpoint']), {'grant_type': 'refresh_token', 'client_id': client['client_id'], 'refresh_token': tokens['refresh_token']})
    check(status == 400 and body['error'] == 'invalid_grant', 'oauth: old refresh token refused')
    status, _, _ = mcp_bearer(rpc('tools/list'), rotated['access_token'], oauth_session)
    check(status == 401, 'oauth: refresh replay revokes the whole grant')

    code = authorize(verifier)
    _, _, tokens = exchange(code, verifier)
    mcp_bearer(rpc('tools/call', {'name': 'afara-site-context', 'arguments': {}}), tokens['access_token'], oauth_session)
    listing = json.loads(subprocess.check_output(['wp', f'--path={ROOT}', '--user=admin', 'eval',
                                                  'echo wp_json_encode(\\Afara\\Admin\\Connections::all());'], text=True))
    app = next((c for c in listing if c.get('type') == 'oauth' and c['name'] == 'Afara CI'), None)
    check(app is not None and app['can_revoke'] and app['afara'] is not None, 'oauth: approved app listed in Connections with its activity')
    oauth_log = json.loads(wp('option', 'get', 'afara_activity_log', '--format=json'))
    check(any(e['connection'] == 'Afara CI' and e['result'] == 'success' for e in oauth_log), 'oauth: Activity log names the OAuth app')
    check(any(e['reason'] == 'afara_invalid_token' for e in oauth_log), 'oauth: forged token logged as refused')
    check(all(tokens['access_token'] not in json.dumps(v) for v in [oauth_log, listing]), 'oauth: tokens never appear in the log or listing')
    stored = wp('db', 'query', "SELECT option_value FROM wp_options WHERE option_name LIKE 'afara_oauth%'", '--skip-column-names')
    check(tokens['access_token'] not in stored and tokens['refresh_token'] not in stored and code not in stored, 'oauth: database holds only hashes of codes and tokens')
    wp('eval', f"\\Afara\\OAuth\\Grants::revoke('{app['uuid']}');")
    status, _, _ = mcp_bearer(rpc('tools/list'), tokens['access_token'], oauth_session)
    check(status == 401, 'oauth: revoking the app in Connect signs it out')

    # Device flow (RFC 8628): register without a redirect, get a code, approve, poll.
    device_grant = 'urn:ietf:params:oauth:grant-type:device_code'
    check(device_grant in asm['grant_types_supported'] and asm.get('device_authorization_endpoint'), 'device: advertised in metadata')
    status, _, body = raw(local(asm['registration_endpoint']), json.dumps({'client_name': 'Afara CLI', 'grant_types': [device_grant, 'refresh_token']}).encode(),
                          {'Content-Type': 'application/json'})
    cli = json.loads(body)
    check(status == 201 and cli['redirect_uris'] == [], 'device: client registers with no redirect URI')
    status, _, started = form(local(asm['device_authorization_endpoint']), {'client_id': cli['client_id'], 'scope': 'afara:read', 'resource': prm['resource']})
    check(status == 200 and len(started['user_code']) == 9 and 'page=afara-device' in started['verification_uri'], 'device: code issued with a verification page')
    poll_fields = {'grant_type': device_grant, 'client_id': cli['client_id'], 'device_code': started['device_code']}
    status, _, body = form(local(asm['token_endpoint']), poll_fields)
    check(status == 400 and body['error'] == 'authorization_pending', 'device: polling waits for approval')
    approved = subprocess.check_output(['wp', f'--path={ROOT}', '--user=admin', 'eval',
                                        f"echo \\Afara\\OAuth\\DeviceFlow::decide('{started['user_code']}', true, get_current_user_id()) ? 'yes' : 'no';"], text=True).strip()
    check(approved == 'yes', 'device: administrator approves the typed code')
    time.sleep(started['interval'] + 1)
    status, _, device_tokens = form(local(asm['token_endpoint']), poll_fields)
    check(status == 200 and device_tokens['token_type'] == 'Bearer', 'device: approved device receives tokens')
    status, _, body = mcp_bearer(rpc('tools/list'), device_tokens['access_token'], oauth_session)
    check(status == 200 and {t['name'] for t in body['result']['tools']} == expected, 'device: token lists the Afara tools')
    status, _, body = form(local(asm['token_endpoint']), poll_fields)
    check(status == 400 and body['error'] == 'expired_token', 'device: code is single-use')
    stored = wp('db', 'query', "SELECT option_value FROM wp_options WHERE option_name LIKE 'afara_oauth%'", '--skip-column-names')
    check(started['device_code'] not in stored and device_tokens['access_token'] not in stored, 'device: device code and tokens stored only as hashes')

    wp('option', 'update', 'afara_oauth_enabled', '0')
    off_status, _, off_body = raw(local(prm_url))
    check(off_status != 200 and b'authorization_servers' not in off_body, 'oauth: switched off means no well-known document')
    check(raw('/wp-json/afara/v1/oauth/metadata')[0] == 404, 'oauth: switched off means no metadata endpoint')
    status, h, _ = raw(pretty, json.dumps(rpc('tools/list')).encode(), {'Content-Type': 'application/json'})
    check(status == 401 and 'Bearer' not in h.get('www-authenticate', ''), 'oauth: switched off means no Bearer challenge')
    wp('option', 'delete', 'afara_oauth_enabled')
    wp('rewrite', 'structure', '')
    print(f'::notice::{checks} WordPress HTTP integration checks passed')
except Exception as error:
    annotate(error)
    raise
except Exception as error:
    print('::error title=WordPress integration::' + str(error).replace('%', '%25').replace('\n', '%0A').replace('\r', '%0D'))
    raise
finally:
    if ep:
        wp('post', 'delete', str(ep['post_id']), '--force')
        wp('post', 'delete', str(ep['attachment_id']), '--force')
    wp('option', 'update', 'afara_read_only', '1')
    wp('option', 'update', 'afara_sandbox_safe_mode', '1')
    if fixture:
        shutil.rmtree(fixture)
    if admin_password_id:
        wp('user', 'application-password', 'delete', 'admin', admin_password_id)
    if editor_id:
        wp('user', 'delete', editor_id, '--yes')
    wp('option', 'delete', 'afara_enabled')
    wp('option', 'delete', 'afara_domain_lock')
    wp('option', 'delete', 'afara_activity_log')
    wp('option', 'delete', 'afara_quiet_mode')
    wp('option', 'delete', 'afara_quiet_users')
    wp('option', 'delete', 'afara_oauth_enabled')
    wp('rewrite', 'structure', '')
