import re
import subprocess

from .models import Finding, Fix, Threat

SECRETS = [
    ("Token Discord", r"[MNO][A-Za-z\d]{23,25}\.[\w-]{6}\.[\w-]{27,}", Threat.MENOS),
    ("Clé privée", r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----", Threat.MENOS),
    ("Clé AWS", r"AKIA[0-9A-Z]{16}", Threat.MENOS),
    ("Token GitHub", r"gh[pousr]_[A-Za-z0-9]{36,}", Threat.MENOS),
    ("Clé Stripe", r"sk_live_[0-9a-zA-Z]{24,}", Threat.MENOS),
    ("Clé Google", r"AIza[0-9A-Za-z\-_]{35}", Threat.ADJUCHAS),
    ("Secret écrit en dur",
     r"(?i)\b(api[_-]?key|secret|token|password|passwd)\b\s*[:=]\s*[\"'][^\"'\s]{8,}[\"']",
     Threat.ADJUCHAS),
]

RISKY = [
    (r"\beval\s*\(", "eval()", Threat.ADJUCHAS,
     "Exécute du texte comme du code : une entrée piégée devient du code.",
     "Remplacer eval() par JSON.parse ou une logique explicite."),
    (r"\bnew Function\s*\(", "new Function()", Threat.GILLIAN,
     "C'est un eval() déguisé.", "Éviter de construire du code à partir de texte."),
    (r"\.innerHTML\s*=", ".innerHTML =", Threat.HOLLOW,
     "Si le texte vient d'un visiteur, il peut injecter du HTML et du script.",
     "Utiliser textContent, ou nettoyer le texte avant."),
    (r"dangerouslySetInnerHTML", "dangerouslySetInnerHTML", Threat.GILLIAN,
     "Injection de HTML brut dans la page.", "Nettoyer le contenu avant de l'injecter."),
]

SKIP = {".git", "node_modules", ".wrangler", "dist", "build", "__pycache__", ".venv", "venv",
        "graphify-out"}
EXTS = {".js", ".mjs", ".cjs", ".ts", ".jsx", ".tsx", ".html", ".py", ".json", ".toml",
        ".yml", ".yaml", ".sh"}
JS_EXTS = {".js", ".mjs", ".cjs", ".ts", ".jsx", ".tsx", ".html"}
IGNORE_NEEDED = [".env", "node_modules", ".wrangler"]


def skipped(path, root):
    return bool(SKIP & set(path.relative_to(root).parts))


def source_files(root):
    for p in root.rglob("*"):
        if p.is_file() and p.suffix.lower() in EXTS and not skipped(p, root) \
                and p.stat().st_size < 1_000_000:
            yield p


def line_of(text, pos):
    return text.count("\n", 0, pos) + 1


def tracked(root, path):
    if not (root / ".git").exists():
        return False
    rel = str(path.relative_to(root))
    return subprocess.run(["git", "-C", str(root), "ls-files", "--error-unmatch", rel],
                          capture_output=True).returncode == 0


def check_file(path, root, out):
    rel = path.relative_to(root).as_posix()
    text = path.read_text(errors="ignore")

    for name, pattern, threat in SECRETS:
        for m in re.finditer(pattern, text):
            ln = line_of(text, m.start())
            found = m.group()
            shown = found[:6] + "…" if len(found) > 6 else "…"
            out.append(Finding(
                f"secret:{rel}:{ln}:{m.start()}", f"{name} dans le code", threat, f"{rel}:{ln}",
                f"Trouvé ligne {ln} : {shown}",
                "Un secret dans le code est compromis dès que le repo est lu par quelqu'un d'autre.",
                "Le déplacer dans un secret Cloudflare (wrangler secret put) et RÉVOQUER l'ancien."))

    if path.suffix.lower() not in JS_EXTS:
        return
    for pattern, label, threat, impact, remedy in RISKY:
        lines = [line_of(text, m.start()) for m in re.finditer(pattern, text)]
        if not lines:
            continue
        # une seule faille par fichier, mais toutes les lignes dans la preuve
        shown = ", ".join(map(str, lines[:20])) + (f" (+{len(lines) - 20})" if len(lines) > 20 else "")
        s = "s" if len(lines) > 1 else ""
        out.append(Finding(f"code:{label}:{rel}", f"Code risqué : {label}", threat,
                           f"{rel}:{lines[0]}", f"« {label} » {len(lines)} fois, ligne{s} {shown}.",
                           impact, remedy))


def check_gitignore(root, out):
    gi = root / ".gitignore"
    if not gi.exists():
        out.append(Finding(
            "git:no-gitignore", "Pas de .gitignore", Threat.GILLIAN, ".gitignore",
            "Le repo n'a pas de .gitignore.",
            "Un .env ou des fichiers locaux peuvent partir sur GitHub par accident.",
            f"Créer un .gitignore avec {', '.join(IGNORE_NEEDED)}.", Fix.GITIGNORE))
        return

    content = gi.read_text(errors="ignore")
    missing = [e for e in IGNORE_NEEDED if e not in content]
    if missing:
        out.append(Finding(
            "git:weak-gitignore", ".gitignore incomplet", Threat.HOLLOW, ".gitignore",
            f"Il manque : {', '.join(missing)}.",
            "Ces fichiers peuvent être commités par accident.",
            f"Ajouter {', '.join(missing)} au .gitignore.", Fix.GITIGNORE))


def check_env(root, out):
    for env in root.rglob(".env*"):
        if not env.is_file() or env.name in (".env.example", ".env.sample") or skipped(env, root):
            continue
        if tracked(root, env):
            rel = env.relative_to(root).as_posix()
            out.append(Finding(
                f"git:env:{rel}", f"{rel} est commité dans git", Threat.MENOS, rel,
                "Le fichier est suivi par git, donc envoyé sur GitHub à chaque push.",
                "Tous les secrets qu'il contient sont lisibles par qui voit le repo.",
                f"git rm --cached {rel}, l'ajouter au .gitignore, puis RÉVOQUER ses secrets."))


def scan(repo, step=lambda _: None):
    out = []
    for f in source_files(repo):
        step(f.relative_to(repo).as_posix())
        check_file(f, repo, out)
    step(".gitignore")
    check_gitignore(repo, out)
    step("Fichiers .env")
    check_env(repo, out)
    return out
