import re
import uuid
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse

import requests

from .models import BankaiError, Finding, Fix, SiteReport, Threat

UA = "Bankai/1.0 (audit autorisé par le propriétaire)"
TIMEOUT = 10
FAKE_ORIGIN = "https://bankai-probe.invalid"

HEADERS = [
    ("content-security-policy", Threat.ADJUCHAS, "Pas de Content-Security-Policy",
     "Une faille XSS pourrait exécuter n'importe quel script sur ta page.",
     "Définir une CSP qui n'autorise que tes propres sources."),
    ("strict-transport-security", Threat.GILLIAN, "Pas de HSTS",
     "Un attaquant sur le réseau peut forcer une connexion en clair.",
     "Envoyer Strict-Transport-Security: max-age=63072000; includeSubDomains."),
    ("x-frame-options", Threat.GILLIAN, "Le site peut être piégé dans une iframe",
     "Clickjacking : un faux site superpose le tien pour voler des clics.",
     "Envoyer X-Frame-Options: DENY."),
    ("x-content-type-options", Threat.HOLLOW, "Pas de X-Content-Type-Options",
     "Le navigateur peut deviner le type d'un fichier et l'exécuter.",
     "Envoyer X-Content-Type-Options: nosniff."),
    ("referrer-policy", Threat.HOLLOW, "Pas de Referrer-Policy",
     "Tes URLs complètes peuvent fuiter vers les sites que tu cites.",
     "Envoyer Referrer-Policy: strict-origin-when-cross-origin."),
    ("permissions-policy", Threat.MOD, "Pas de Permissions-Policy",
     "Caméra, micro et géolocalisation restent demandables par défaut.",
     "Envoyer Permissions-Policy: camera=(), microphone=(), geolocation=()."),
]

FILES = [".env", ".env.production", ".git/HEAD", ".git/config", "wrangler.toml",
         "config.json", ".DS_Store", "backup.zip", "dump.sql"]
MARKERS = ("ref: refs/", "[core]", "private key", "api_key", "secret", "token",
           "password", "account_id")


def get(url, session=None, headers=None, follow=False):
    try:
        return (session or requests).get(url, timeout=TIMEOUT, allow_redirects=follow,
                                         headers={"User-Agent": UA, **(headers or {})})
    except requests.RequestException:
        return None


def cookies_of(resp):
    raw = resp.raw.headers
    fn = getattr(raw, "getlist", None) or getattr(raw, "get_all", None)
    return list(fn("set-cookie") or []) if fn else []


def hosts_in(html, pattern):
    return {urlparse(u).netloc for u in re.findall(pattern, html, re.I) if u.startswith("http")}


def check_headers(report, url, headers):
    for name, threat, title, impact, remedy in HEADERS:
        if name not in headers:
            report.findings.append(Finding(f"header:{name}", title, threat, url,
                                           f"La réponse n'a pas d'en-tête « {name} ».",
                                           impact, remedy, Fix.SHIELD))

    for name in ("x-powered-by", "server", "x-aspnet-version"):
        val = headers.get(name, "")
        if val and val.lower() != "cloudflare":
            report.findings.append(Finding(
                f"leak:{name}", f"L'en-tête {name} révèle ta techno", Threat.HOLLOW, url,
                f"{name}: {val}", "Indique à un attaquant quelles failles connues essayer.",
                f"Retirer l'en-tête {name}.", Fix.SHIELD))


def check_cookies(report, url, resp):
    for c in cookies_of(resp):
        missing = [f for f in ("secure", "httponly", "samesite") if f not in c.lower()]
        if not missing:
            continue
        name = c.split("=", 1)[0].strip()
        report.findings.append(Finding(
            f"cookie:{name}", f"Le cookie « {name} » est mal protégé", Threat.GILLIAN, url,
            f"Drapeaux absents : {', '.join(missing)}.",
            "Le cookie peut être volé par un script ou envoyé vers un autre site.",
            "Ajouter Secure, HttpOnly et SameSite=Lax à ce cookie."))


def check_cors(report, url, session):
    r = get(url, session, {"Origin": FAKE_ORIGIN})
    if r is None:
        return
    allowed = r.headers.get("access-control-allow-origin", "")
    creds = r.headers.get("access-control-allow-credentials", "").lower() == "true"
    if allowed == FAKE_ORIGIN:
        report.findings.append(Finding(
            "cors:reflect", "Le CORS accepte n'importe quel site",
            Threat.MENOS if creds else Threat.ADJUCHAS, url,
            f"Origine inventée renvoyée telle quelle (credentials : {'oui' if creds else 'non'}).",
            "N'importe quel site peut lire tes réponses, y compris au nom d'un visiteur connecté.",
            "Comparer l'Origin à une liste fixe de tes domaines au lieu de la renvoyer."))
    elif allowed == "*":
        report.findings.append(Finding(
            "cors:wildcard", "Le CORS est ouvert à tous (*)", Threat.GILLIAN, url,
            "Access-Control-Allow-Origin: *", "N'importe quel site peut lire tes réponses.",
            "Limiter Access-Control-Allow-Origin à tes propres domaines."))


def check_https(report, site):
    r = get(f"http://{site.netloc}{site.path or '/'}")
    if r is not None and r.status_code < 300:
        report.findings.append(Finding(
            "https:redirect", "HTTP ne redirige pas vers HTTPS", Threat.GILLIAN,
            f"http://{site.netloc}", f"http:// répond {r.status_code} au lieu de rediriger.",
            "Une visite en http:// circule en clair et peut être lue ou modifiée.",
            "Rediriger tout le trafic http:// vers https:// (301).", Fix.SHIELD))


def check_files(report, root):
    decoy = get(f"{root}/bankai-{uuid.uuid4().hex[:8]}")
    fallback = decoy.text[:4000] if decoy is not None and decoy.status_code == 200 else None

    with ThreadPoolExecutor(max_workers=4) as pool:
        results = pool.map(lambda p: get(f"{root}/{p}"), FILES)
        for path, r in zip(FILES, results):
            if r is None or r.status_code != 200:
                continue
            body = r.text[:4000]
            if body == fallback or "<html" in body[:600].lower():
                continue
            secrets = any(m in body.lower() for m in MARKERS)
            report.findings.append(Finding(
                f"file:{path}", f"/{path} est accessible publiquement",
                Threat.MENOS if secrets else Threat.GILLIAN, f"{root}/{path}",
                "Répond 200" + (" et contient des secrets." if secrets else "."),
                "N'importe qui peut télécharger ce fichier.",
                f"Bloquer /{path} et ne plus le déployer. Révoquer tout secret qu'il contenait."))


def scan(url, step=lambda _: None):
    site = urlparse(url)
    if site.scheme not in ("http", "https") or not site.netloc:
        raise BankaiError(f"URL invalide : {url} (exemple : https://mon-site.com)")

    report = SiteReport()
    session = requests.Session()

    step("Page d'accueil")
    home = get(url, session, follow=True)
    if home is None:
        raise BankaiError(f"Le site {url} ne répond pas. Vérifie l'URL et qu'il est en ligne.")
    url = home.url  # la page finale, après redirections (ex. vers www.)
    site = urlparse(url)

    report.script_hosts = hosts_in(home.text, r"<script[^>]+src=[\"']([^\"']+)")
    report.style_hosts = hosts_in(home.text, r"<link[^>]+href=[\"']([^\"']+)")
    if "fonts.googleapis.com" in report.style_hosts:
        report.font_hosts.add("fonts.gstatic.com")

    step("En-têtes de sécurité")
    check_headers(report, url, home.headers)
    step("Cookies")
    check_cookies(report, url, home)
    step("CORS")
    check_cors(report, url, session)
    if site.scheme == "https":
        step("Redirection HTTPS")
        check_https(report, site)
    step("Fichiers sensibles")
    check_files(report, f"{site.scheme}://{site.netloc}")
    return report
