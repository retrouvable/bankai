from datetime import date

from .models import Fix
from .scoring import form, reiatsu

SHIELD_FILE = "bankai-shield.js"
REPORT_FILE = "SECURITY_AUDIT.md"
IGNORE_LINES = [".env", ".env.*", "!.env.example", "node_modules/", ".wrangler/", "*.log"]

SHIELD = """\
const CSP = [
{csp}
].join("; ");

const SECURITY_HEADERS = {{
  "Content-Security-Policy": CSP,
  "Strict-Transport-Security": "max-age=63072000; includeSubDomains",
  "X-Frame-Options": "DENY",
  "X-Content-Type-Options": "nosniff",
  "Referrer-Policy": "strict-origin-when-cross-origin",
  "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
}};

const LEAKY = ["Server", "X-Powered-By", "X-AspNet-Version"];

export function shield(handler) {{
  return async (request, env, ctx) => {{
    const url = new URL(request.url);
    if (url.protocol === "http:") {{
      url.protocol = "https:";
      return Response.redirect(url.toString(), 301);
    }}

    const res = await handler(request, env, ctx);
    const headers = new Headers(res.headers);
    for (const [k, v] of Object.entries(SECURITY_HEADERS)) {{
      if (!headers.has(k)) headers.set(k, v);
    }}
    for (const k of LEAKY) headers.delete(k);

    return new Response(res.body, {{ status: res.status, statusText: res.statusText, headers }});
  }};
}}
"""


def sources(extra, hosts):
    return " ".join(["'self'", extra] + sorted("https://" + h for h in hosts))


def build_csp(site):
    rules = [
        "default-src 'self'",
        "script-src " + sources("'unsafe-inline'", site.script_hosts),
        "style-src " + sources("'unsafe-inline'", site.style_hosts),
        "font-src " + sources("data:", site.font_hosts),
        "img-src 'self' data: https:",
        "connect-src 'self' https:",
        "frame-ancestors 'none'",
        "base-uri 'self'",
        "form-action 'self'",
        "object-src 'none'",
    ]
    return ",\n".join(f'  "{r}"' for r in rules)


def write_shield(repo, site):
    (repo / SHIELD_FILE).write_text(SHIELD.format(csp=build_csp(site)), encoding="utf-8")
    return f"{SHIELD_FILE} : en-têtes de sécurité + redirection HTTPS, à brancher dans ton Worker"


def harden_gitignore(repo):
    gi = repo / ".gitignore"
    content = gi.read_text(errors="ignore") if gi.exists() else ""
    missing = [l for l in IGNORE_LINES if l not in content.splitlines()]
    if not missing:
        return None
    if content and not content.endswith("\n"):
        content += "\n"
    gi.write_text(content + "\n".join(missing) + "\n", encoding="utf-8")
    return f".gitignore : {len(missing)} règle(s) ajoutée(s) ({', '.join(missing)})"


def state(f):
    if f.killed:
        return "☠ purifiée"
    if f.shielded:
        return "🛡 bouclier à brancher"
    return f.threat.label


def write_report(repo, findings, before, after, shielded):
    todo = [f for f in findings if not f.killed and not f.shielded]
    todo_md = "\n".join(f"- [ ] **{f.title}** (`{f.where}`) : {f.remedy}" for f in todo)
    if any(f.shielded for f in findings):
        todo_md = (f"- [ ] **Brancher `{SHIELD_FILE}` dans ton Worker** : tant que ce n'est pas "
                   f"fait, les en-têtes et la redirection HTTPS ne sont pas actifs.\n" + todo_md)
    rows = "\n".join(
        f"| {state(f)} | {f.title} | `{f.where}` | "
        f"{f.remedy.replace('|', '/')} |" for f in findings)
    end = form(after)
    score = f"**Reiatsu : {before}/100 → {after}/100** ({end.kanji} {end.name})"
    if shielded != after:
        score += f", **{shielded}/100** une fois le bouclier branché"

    report = f"""# 卍解 BANKAI — rapport d'audit

_Audit du {date.today():%d/%m/%Y}, mené par le propriétaire sur sa propre infrastructure._

{score}

## Ce qui reste à faire à la main

{todo_md.strip() or "- Rien, tout est purifié."}

## Toutes les failles

| État | Faille | Où | Correctif |
|------|--------|----|-----------|
{rows}
"""
    (repo / REPORT_FILE).write_text(report, encoding="utf-8")
    return f"{REPORT_FILE} : le rapport complet avec la liste de ce qu'il reste à faire"


def apply(repo, site, findings, before):
    written = []
    if any(f.fix == Fix.SHIELD for f in findings):
        written.append(write_shield(repo, site))
    if any(f.fix == Fix.GITIGNORE for f in findings):
        msg = harden_gitignore(repo)
        if msg:
            written.append(msg)

    for f in findings:
        if f.fix == Fix.GITIGNORE:
            f.killed = True
        elif f.fix == Fix.SHIELD:
            f.shielded = True

    written.append(write_report(repo, findings, before, reiatsu(findings),
                                reiatsu(findings, with_shield=True)))
    return written
