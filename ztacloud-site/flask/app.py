from flask import Flask, request
import os

app = Flask(__name__)

@app.route("/", defaults={"path": ""})
@app.route("/<path:path>")
def catchall(path):
    # try every possible header name Pomerium might use
    email  = (request.headers.get("email") or
              request.headers.get("Email") or
              request.headers.get("X-Pomerium-Claim-Email") or
              "unknown")
    groups = (request.headers.get("groups") or
              request.headers.get("Groups") or
              request.headers.get("X-Pomerium-Claim-Groups") or
              "none")
    sub    = (request.headers.get("sub") or
              request.headers.get("Sub") or
              request.headers.get("X-Pomerium-Claim-Sub") or
              "none")
    site   = os.environ.get("DEPLOYMENT_SITE", "ztacloud")
    # dump all headers for debugging
    all_headers = dict(request.headers)
    return f"""<!DOCTYPE html>
<html><head><style>
body{{background:#0a1628;color:#e2e8f0;font-family:sans-serif;padding:40px;margin:0}}
.card{{background:#1e293b;border:1px solid #22c55e;border-radius:12px;padding:40px;max-width:600px}}
h2{{color:#22c55e;margin-top:0}}p{{margin:8px 0}}b{{color:#94a3b8}}span{{color:#fff}}
.badge{{background:#16a34a;color:#fff;padding:2px 10px;border-radius:20px;font-size:12px}}
.site{{color:#64748b;font-size:13px;margin-top:20px}}
pre{{background:#0f172a;padding:12px;border-radius:8px;font-size:11px;overflow-x:auto;color:#94a3b8}}
</style></head><body>
<div class="card">
  <h2>&#x2705; You Are Inside the Zero Trust Protected Zone</h2>
  <p>Pomerium verified your identity via Keycloak OIDC.</p>
  <p>Access is controlled by group membership — no hardcoded users.</p>
  <hr style="border-color:#334155;margin:20px 0">
  <p><b>Identity:</b> <span>{email}</span></p>
  <p><b>Groups:</b> <span class="badge">{groups}</span></p>
  <p><b>Subject:</b> <span>{sub}</span></p>
  <p class="site">&#x1F310; Served from: <b>{site}</b> (DR secondary) via Tailscale WireGuard mesh</p>
  <hr style="border-color:#334155;margin:20px 0">
  <p><b style="color:#64748b;font-size:12px">DEBUG — headers received (remove before exam):</b></p>
  <pre>{all_headers}</pre>
</div>
</body></html>"""

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
