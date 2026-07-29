from flask import Flask, request, render_template_string

app = Flask(__name__)

TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
  <title>ZTA Demo - Frontend (Web Tier)</title>
  <style>
    body { font-family: -apple-system, sans-serif; max-width: 700px; margin: 60px auto; padding: 0 20px; background: #0f172a; color: #e2e8f0; }
    h1 { color: #38bdf8; }
    .card { background: #1e293b; border-radius: 8px; padding: 24px; margin-top: 24px; }
    .row { display: flex; justify-content: space-between; padding: 10px 0; border-bottom: 1px solid #334155; }
    .row:last-child { border-bottom: none; }
    .label { color: #94a3b8; }
    .value { font-weight: 600; }
    .badge { display: inline-block; padding: 4px 10px; border-radius: 4px; font-size: 0.85em; font-weight: 600; }
    .badge.engineers { background: #1e40af; color: #bfdbfe; }
    .badge.admins { background: #7c2d12; color: #fed7aa; }
    .badge.unknown { background: #475569; color: #cbd5e1; }
    .missing { color: #f87171; font-style: italic; }
    .footer { margin-top: 20px; font-size: 0.85em; color: #64748b; }
  </style>
</head>
<body>
  <h1>FRONTEND — Web Tier</h1>
  <p>You are authenticated via Keycloak &rarr; Pomerium. Identity below was forwarded by Pomerium as request headers.</p>
  <div class="card">
    <div class="row"><span class="label">Email</span><span class="value">{{ email or "" }}{% if not email %}<span class="missing">not present</span>{% endif %}</span></div>
    <div class="row"><span class="label">Subject ID</span><span class="value">{{ sub or "" }}{% if not sub %}<span class="missing">not present</span>{% endif %}</span></div>
    <div class="row">
      <span class="label">Group / Privilege</span>
      <span class="value">
        {% if groups %}
          {% for g in groups %}<span class="badge {{ g }}">{{ g }}</span> {% endfor %}
        {% else %}
          <span class="badge unknown">no group claim</span>
        {% endif %}
      </span>
    </div>
  </div>
  <p class="footer">Header source: Pomerium (pass_identity_headers + jwt_claims_headers). This page only renders what Pomerium forwarded — it performs no authentication itself.</p>
</body>
</html>
"""

@app.route("/")
def index():
    email = request.headers.get("Email") or request.headers.get("X-Pomerium-Claim-Email")
    sub = request.headers.get("Sub") or request.headers.get("X-Pomerium-Claim-Sub")
    groups_raw = request.headers.get("Groups") or request.headers.get("X-Pomerium-Claim-Groups") or ""
    groups = [g.strip() for g in groups_raw.split(",") if g.strip()]
    return render_template_string(TEMPLATE, email=email, sub=sub, groups=groups)

@app.route("/api/health")
def health():
    return {"status": "ok", "service": "frontend-identity"}

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
