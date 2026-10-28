#!/usr/bin/env python3
"""
End-to-end test: WP Fleet hub against a local WordPress with goo1 Claude Bridge.

Env: FLEET (default http://localhost:8787), WP (default http://localhost:8080),
FLEET_USER / FLEET_PASS (hub admin), WP_USER / WP_PASS (WordPress admin).
The hub must run with FLEET_ALLOW_HTTP_SITES=1 and a fresh database.
"""
import base64, hashlib, hmac, http.cookiejar, json, os, re, struct, sys, threading, time, urllib.parse, urllib.request

FLEET = os.environ.get("FLEET", "http://localhost:8787")
WP = os.environ.get("WP", "http://localhost:8080")
FU, FP = os.environ["FLEET_USER"], os.environ["FLEET_PASS"]
WU, WPW = os.environ["WP_USER"], os.environ["WP_PASS"]
fails = 0


def check(name, cond, info=""):
    global fails
    print(("PASS " if cond else "FAIL ") + name + ("" if cond else "  -> " + str(info)[:500]))
    if not cond:
        fails += 1


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


jar = http.cookiejar.CookieJar()
op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar), NoRedirect)


def req(url, data=None, headers=None, method=None):
    h = dict(headers or {})
    if isinstance(data, dict):
        data = urllib.parse.urlencode(data).encode()
        h.setdefault("Content-Type", "application/x-www-form-urlencoded")
    r = urllib.request.Request(url, data=data, headers=h, method=method)
    try:
        resp = op.open(r, timeout=180)
        return resp.status, {k.lower(): v for k, v in resp.headers.items()}, resp.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, {k.lower(): v for k, v in e.headers.items()}, e.read().decode()


def totp(secret, t=None):
    key = base64.b32decode(secret + "=" * (-len(secret) % 8))
    counter = int((t or time.time()) // 30)
    hm = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    o = hm[-1] & 15
    return "%06d" % ((struct.unpack(">I", hm[o:o + 4])[0] & 0x7FFFFFFF) % 1000000)


def csrf_of(body):
    m = re.search(r'name="csrf" value="([^"]+)"', body)
    return m.group(1) if m else ""


# ---------------- hub login + TOTP enrolment ----------------
s, h, b = req(FLEET + "/admin")
check("admin redirects to login", s == 302 and "/login" in h.get("location", ""), (s, h.get("location")))
s, h, b = req(FLEET + "/login", {"username": FU, "password": "wrong-password-x", "code": "", "next": "/admin"})
check("wrong password refused", s == 401, s)
s, h, b = req(FLEET + "/login", {"username": FU, "password": FP, "code": "", "next": "/admin"})
check("password login -> TOTP enrolment", s == 302 and "/totp" in h.get("location", ""), (s, h.get("location")))
s, h, b = req(FLEET + "/admin")
check("admin still blocked before TOTP", s == 302 and "/totp" in h.get("location", ""), (s, h.get("location")))
s, h, b = req(FLEET + "/totp")
secret = re.search(r"Key: <code>([A-Z2-7 ]+)</code>", b).group(1).replace(" ", "")
check("TOTP page shows QR", "<svg" in b, b[:200])
s, h, b2 = req(FLEET + "/totp", {"csrf": csrf_of(b), "code": "000000", "next": "/admin"})
check("wrong TOTP refused", s == 302 and "error" in h.get("location", ""), h.get("location"))
s, h, b2 = req(FLEET + "/totp", {"csrf": csrf_of(b), "code": totp(secret), "next": "/admin"})
check("TOTP activated", s == 302 and h.get("location") == "/admin", (s, h.get("location")))
s, h, b2 = req(FLEET + "/totp")
check("TOTP page after activation goes to admin", s == 302 and h.get("location") == "/admin", (s, h.get("location")))
s, h, b = req(FLEET + "/admin")
check("admin page", s == 200 and "Add a site" in b, s)
CSRF = csrf_of(b)
check("CSP header on admin page", "default-src 'none'" in h.get("content-security-policy", ""), h.get("content-security-policy"))

# ---------------- CSRF / origin ----------------
s, h, b = req(FLEET + "/admin/sites", {"csrf": "nope", "url": WP})
check("add site without CSRF refused", s == 403, s)
s, h, b = req(FLEET + "/admin/sites", {"csrf": CSRF, "url": WP}, {"Origin": "https://evil.example"})
check("add site from foreign origin refused", s == 403, s)

# ---------------- add + connect a site ----------------
s, h, b = req(FLEET + "/admin/sites", {"csrf": CSRF, "url": WP, "name": "Test WP"})
loc = h.get("location", "")
check("add site redirects to the site's consent page", s == 302 and "/goo1-mcp-oauth/authorize" in loc, (s, loc, b[:300]))
# WordPress login
req(WP + "/wp-login.php")
req(WP + "/wp-login.php", {"log": WU, "pwd": WPW, "wp-submit": "Log In", "testcookie": "1"}, {"Cookie": "wordpress_test_cookie=WP%20Cookie%20check"})
s, h, b = req(loc)
check("Bridge consent page", s == 200 and "Authorize MCP Connector" in b and "WP Fleet" in b, (s, b[:300]))
nonce = re.search(r'name="_wpnonce" value="([^"]+)"', b).group(1)
q = dict(urllib.parse.parse_qsl(urllib.parse.urlparse(loc).query))
form = {k: q[k] for k in ("client_id", "redirect_uri", "response_type", "state", "code_challenge", "code_challenge_method")}
form.update({"_wpnonce": nonce, "_wp_http_referer": "/", "goo1_oauth_scope": "full", "goo1_oauth_decision": "approve"})
s, h, b = req(WP + "/goo1-mcp-oauth/authorize", form, {"Referer": WP + "/goo1-mcp-oauth/authorize"})
cb = h.get("location", "")
check("Bridge redirects back to the hub", s == 302 and cb.startswith(FLEET + "/sites/callback"), (s, cb))
s, h, b = req(cb)
check("hub callback connects the site (no message text in URL)", s == 302 and h.get("location") == "/admin", (s, h.get("location")))
s, h, b = req(FLEET + "/admin")
check("flash message shown once", "is connected" in b, b[:300])
check("site listed as connected", "connected" in b and "localhost-8080" in b, b[:200])
s, h, b = req(FLEET + "/admin")
check("flash message gone on reload", "is connected" not in b, "")
s, h, b = req(cb)
s, h, b = req(FLEET + "/admin")
check("callback cannot be replayed", "expired" in b or "already used" in b, b[:300])

# reconnect that is abandoned must not break the working connection
s, h, b = req(FLEET + "/admin/sites/localhost-8080/connect", {"csrf": CSRF})
check("reconnect starts a new authorization", s == 302 and "/goo1-mcp-oauth/authorize" in h.get("location", ""), (s, h.get("location")))

# ---------------- Claude as OAuth client of the hub ----------------
s, h, b = req(FLEET + "/.well-known/oauth-protected-resource/mcp")
prm = json.loads(b)
check("protected resource metadata", prm["resource"] == FLEET + "/mcp", prm)
s, h, b = req(FLEET + "/.well-known/oauth-authorization-server")
asm = json.loads(b)
check("AS metadata S256 only", asm["code_challenge_methods_supported"] == ["S256"], asm)
s, h, b = req(FLEET + "/oauth/register", json.dumps({"client_name": "x", "redirect_uris": ["http://evil.example/cb"]}).encode(), {"Content-Type": "application/json"})
check("DCR rejects non-https redirect", s == 400, s)
s, h, b = req(FLEET + "/oauth/register", json.dumps({"client_name": "x", "redirect_uris": ["https://evil.example/cb"]}).encode(), {"Content-Type": "application/json"})
check("DCR rejects https host outside the allowlist", s == 400 and "claude.ai" in b, (s, b))
s, h, b = req(FLEET + "/oauth/register", json.dumps({"client_name": "x", "redirect_uris": ["https://claude.ai/api/mcp/auth_callback"]}).encode(), {"Content-Type": "application/json"})
check("DCR accepts claude.ai", s == 201 and h.get("cache-control") == "no-store", (s, h.get("cache-control")))
s, h, b = req(FLEET + "/oauth/register", ("x" * 70000).encode(), {"Content-Type": "application/json"})
check("oversized body refused", s == 413, s)
REDIR = "http://127.0.0.1:9999/cb"
s, h, b = req(FLEET + "/oauth/register", json.dumps({"client_name": "Claude Test", "redirect_uris": [REDIR], "token_endpoint_auth_method": "none"}).encode(), {"Content-Type": "application/json"})
cid = json.loads(b)["client_id"]
check("DCR ok", s == 201 and cid.startswith("wpf_client_"), (s, b))


CONSENT = {}


def connect(scope, all_sites=True, sites=(), ver=None):
    ver = ver or base64.urlsafe_b64encode(os.urandom(32)).rstrip(b"=").decode()
    chal = base64.urlsafe_b64encode(hashlib.sha256(ver.encode()).digest()).rstrip(b"=").decode()
    q = {"client_id": cid, "redirect_uri": REDIR, "response_type": "code", "state": "s1", "code_challenge": chal, "code_challenge_method": "S256"}
    s, h, b = req(FLEET + "/oauth/authorize?" + urllib.parse.urlencode(q))
    assert s == 200, (s, b[:300])
    CONSENT["page"] = b
    f = {**q, "csrf": csrf_of(b), "grant_scope": scope, "decision": "approve"}
    if all_sites:
        f["all_sites"] = "1"
    for x in sites:
        f["site_" + x] = "1"
    s, h, b = req(FLEET + "/oauth/authorize", f)
    loc = h.get("location", "")
    code = urllib.parse.parse_qs(urllib.parse.urlparse(loc).query)["code"][0]
    s, h, b = req(FLEET + "/oauth/token", {"grant_type": "authorization_code", "code": code, "redirect_uri": REDIR, "code_verifier": ver, "client_id": cid})
    return s, json.loads(b), code, ver


# authorize errors are never redirected to unknown URIs
s, h, b = req(FLEET + "/oauth/authorize?" + urllib.parse.urlencode({"client_id": cid, "redirect_uri": "https://evil.example/cb", "response_type": "code", "code_challenge": "x", "code_challenge_method": "S256"}))
check("authorize with unregistered redirect shows error", s == 400, s)
s, h, b = req(FLEET + "/oauth/authorize?" + urllib.parse.urlencode({"client_id": cid, "redirect_uri": REDIR, "response_type": "code", "code_challenge": "x", "code_challenge_method": "plain"}))
check("plain PKCE refused", s == 302 and "invalid_request" in h.get("location", ""), h.get("location"))

s, tokx, code, ver = connect("write")
s, h, b = req(FLEET + "/oauth/token", {"grant_type": "authorization_code", "code": code, "redirect_uri": REDIR, "code_verifier": ver, "client_id": cid})
check("code is single use", s == 400, s)
s, h, b = req(FLEET + "/mcp", json.dumps({"jsonrpc": "2.0", "id": 1, "method": "ping"}).encode(), {"Content-Type": "application/json", "Authorization": "Bearer " + tokx["access_token"]})
check("code reuse revokes the tokens issued with it", s == 401, s)
s, j, _, _ = connect("read", ver="short")
check("short PKCE verifier refused", s == 400 and "PKCE" in json.dumps(j), (s, j))
s, tok, code, ver = connect("write")
check("token exchange", s == 200 and tok["scope"] == "write" and tok["access_token"].startswith("wpf_at_"), tok)
check("consent page defaults to read-only", re.search(r'value="read" checked', CONSENT["page"]) and not re.search(r'value="write" checked', CONSENT["page"]), "")
AT = tok["access_token"]


def mcp(method, params=None, at=None):
    s, h, b = req(FLEET + "/mcp", json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params or {}}).encode(), {"Content-Type": "application/json", "Authorization": "Bearer " + (at or AT)})
    return s, h, (json.loads(b) if b else None)


def call(tool, args, at=None):
    s, h, r = mcp("tools/call", {"name": tool, "arguments": args}, at)
    res = r.get("result", {}) if r else {}
    txt = (res.get("content") or [{}])[0].get("text", "")
    try:
        p = json.loads(txt)
    except Exception:
        p = txt
    return res.get("isError"), p


s, h, r = mcp("initialize", {"protocolVersion": "2025-06-18"}, at="wpf_at_wrong")
check("MCP 401 with metadata pointer", s == 401 and "oauth-protected-resource/mcp" in h.get("www-authenticate", ""), (s, h.get("www-authenticate")))
s, h, r = mcp("initialize", {"protocolVersion": "2025-06-18"})
check("initialize", s == 200 and "localhost-8080" in r["result"]["instructions"], r)
s, h, r = mcp("tools/list")
names = [t["name"] for t in r["result"]["tools"]]
check("five fleet tools", names == ["fleet_sites", "fleet_find_tools", "fleet_describe_tool", "fleet_call_read", "fleet_call_write"], names)
print("     tools/list size:", len(json.dumps(r["result"]["tools"])), "chars")

err, p = call("fleet_sites", {})
check("fleet_sites", not err and p["sites"][0]["site"] == "localhost-8080" and p["sites"][0]["status"] == "connected", p)
err, p = call("fleet_find_tools", {"query": "plugin update"})
check("find tools", not err and "wp_update_plugin" in [t["name"] for t in p["tools"][:3]], p)
err, p = call("fleet_find_tools", {})
check("find all tool names", not err and p["total"] > 50, p.get("total") if isinstance(p, dict) else p)
err, p = call("fleet_describe_tool", {"name": "wp_list_posts,nope"})
check("describe", not err and p["tools"][0]["inputSchema"]["type"] == "object" and p["unknown"] == ["nope"], p)

err, p = call("fleet_call_read", {"site": "localhost-8080", "tool": "wp_list_posts", "arguments": {"per_page": 2}})
check("call_read single site", not err and p.get("success") is True, p)
err, p = call("fleet_call_read", {"site": "*", "tool": "wp_site_health", "arguments": {}})
check("call_read all sites", not err and "localhost-8080" in p["results"] and p["results"]["localhost-8080"]["isError"] is False, p)
err, p = call("fleet_call_read", {"site": "localhost-8080", "tool": "wp_delete_post", "arguments": {"id": 1}})
check("call_read refuses write tool", err and "fleet_call_write" in json.dumps(p), p)
err, p = call("fleet_call_read", {"site": "other.example", "tool": "wp_list_posts"})
check("unknown site refused", err, p)
err, p = call("fleet_call_write", {"site": "localhost-8080", "tool": "wp_create_post", "arguments": {"title": "fleet test", "status": "draft"}})
pid = p.get("data", {}).get("id") if isinstance(p, dict) else None
check("call_write create post", not err and pid, p)
err, p = call("fleet_call_write", {"site": "localhost-8080", "tool": "wp_delete_post", "arguments": {"id": pid, "force": True}})
check("call_write delete post", not err, p)
err, p = call("fleet_call_write", {"site": "*", "tool": "wp_delete_post", "arguments": {"id": 1}})
check("call_write refuses multi-site", err, p)
err, p = call("fleet_call_read", {"site": "localhost-8080", "tool": "wp_get_options", "arguments": {"keys": "goo1_mcp_api_keys"}})
check("site redaction passes through", not err and p["data"]["goo1_mcp_api_keys"] == "[redacted]", p)

# site access token refresh (force expiry in DB)
import sqlite3
db = sqlite3.connect(os.environ["FLEET_DB_PATH"])
old_enc = db.execute("SELECT refresh_token_enc FROM sites").fetchone()[0]
db.execute("UPDATE sites SET access_expires = 0"); db.commit()
err, p = call("fleet_call_read", {"site": "localhost-8080", "tool": "wp_list_posts", "arguments": {"per_page": 1}})
new_enc = db.execute("SELECT refresh_token_enc FROM sites").fetchone()[0]
check("site token refreshed and rotated", not err and old_enc != new_enc, p)
check("tokens stored encrypted", new_enc.startswith("v1.") and "goo1_rt_" not in new_enc, new_enc[:20])

# read-only connection
s, tokr, _, _ = connect("read")
err, p = call("fleet_call_write", {"site": "localhost-8080", "tool": "wp_create_post", "arguments": {"title": "x"}}, at=tokr["access_token"])
check("read connection cannot write", err and "read-only" in json.dumps(p), p)
err, p = call("fleet_call_read", {"site": "localhost-8080", "tool": "wp_list_posts", "arguments": {}}, at=tokr["access_token"])
check("read connection can read", not err, p)

# site-restricted connection (no sites)
s, toks, _, _ = connect("write", all_sites=False, sites=())
err, p = call("fleet_sites", {}, at=toks["access_token"])
check("connection limited to no sites sees none", not err and p["sites"] == [], p)
err, p = call("fleet_call_read", {"site": "localhost-8080", "tool": "wp_list_posts"}, at=toks["access_token"])
check("restricted connection cannot call", err, p)

# refresh rotation + replay
s, h, b = req(FLEET + "/oauth/token", {"grant_type": "refresh_token", "refresh_token": tok["refresh_token"], "client_id": cid})
t2 = json.loads(b)
check("refresh rotates", s == 200 and t2["refresh_token"] != tok["refresh_token"], b)
s, h, b = req(FLEET + "/oauth/token", {"grant_type": "refresh_token", "refresh_token": tok["refresh_token"], "client_id": cid})
check("one grace redemption returns the identical tokens", s == 200 and json.loads(b)["refresh_token"] == t2["refresh_token"], b)
s, h, b = req(FLEET + "/oauth/token", {"grant_type": "refresh_token", "refresh_token": tok["refresh_token"], "client_id": cid})
check("second replay revokes", s == 400 and "revoked" in b, b)
s, h, r = mcp("tools/list", at=t2["access_token"])
check("revoked family's access token dead", s == 401, s)

# parallel refresh of the same token: identical answers, one chain
s, tp, _, _ = connect("read")
res = []
def refresh_once():
    res.append(req(FLEET + "/oauth/token", {"grant_type": "refresh_token", "refresh_token": tp["refresh_token"], "client_id": cid}))
th = [threading.Thread(target=refresh_once) for _ in range(2)]
[t.start() for t in th]; [t.join() for t in th]
ok = [json.loads(x[2]) for x in res if x[0] == 200]
check("parallel refresh: both succeed with the same tokens", len(ok) == 2 and ok[0]["refresh_token"] == ok[1]["refresh_token"], [x[0] for x in res])
s, h, b = req(FLEET + "/oauth/token", {"grant_type": "refresh_token", "refresh_token": ok[0]["refresh_token"], "client_id": cid}) if ok else (0, {}, "")
check("the single new chain keeps working", s == 200, (s, b))

# admin revoke of a connection
s, h, b = req(FLEET + "/admin")
fam = re.findall(r"/admin/connections/([A-Za-z0-9_-]+)/revoke", b)
check("connections listed", len(fam) >= 2, fam)
for f in fam:
    req(FLEET + "/admin/connections/" + f + "/revoke", {"csrf": csrf_of(b)})
s, h, r = mcp("tools/list", at=tokr["access_token"])
check("admin disconnect kills tokens", s == 401, s)

# audit
s, h, b = req(FLEET + "/admin/audit")
check("audit log shows calls", "call_read" in b and "call_write" in b and "site_connected" in b, b[:300])

# unredacted is stripped from read calls (need a fresh connection; the admin revoke above killed the others)
s, tu, _, _ = connect("read")
s, h, r = mcp("tools/call", {"name": "fleet_call_read", "arguments": {"site": "localhost-8080", "tool": "wp_list_posts", "arguments": {"per_page": 1, "unredacted": True}}}, at=tu["access_token"])
check("unredacted ignored on read calls", "was ignored" in json.dumps(r), json.dumps(r)[:300])

# HSTS only on https; security headers present
s, h, b = req(FLEET + "/login")
check("no HSTS on http dev origin", "strict-transport-security" not in h, h.get("strict-transport-security"))

# throttle: parallel wrong logins cannot slip past the limit
codes = []
def bad_login(i):
    codes.append(req(FLEET + "/login", {"username": FU, "password": "bad-" + str(i) + "-xxxxxxxx", "code": "123456"})[0])
th = [threading.Thread(target=bad_login, args=(i,)) for i in range(12)]
[t.start() for t in th]; [t.join() for t in th]
check("parallel login attempts throttled at 8", codes.count(401) == 8 and codes.count(429) == 4, sorted(codes))

print("\nFAILS:", fails)
sys.exit(1 if fails else 0)
