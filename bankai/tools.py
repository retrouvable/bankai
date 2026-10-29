"""卍 `bankai setup` : télécharge les outils du scan actif dans le dossier de BANKAI.

Rien n'est installé sur le système et rien ne demande sudo. Chaque outil vient
de sa source officielle et garde sa propre licence.
"""
import io
import os
import platform
import shlex
import shutil
import subprocess
import sys
import tarfile
import time
import zipfile
from pathlib import Path

import requests

HOME = Path(os.environ.get("BANKAI_HOME", Path.home() / ".local" / "share" / "bankai"))
BIN = HOME / "bin"
SRC = HOME / "src"
TIMEOUT = 60
UA = "Bankai-setup"

# binaires Go publiés par ProjectDiscovery : (nom, dépôt GitHub)
RELEASES = [("nuclei", "projectdiscovery/nuclei"), ("subfinder", "projectdiscovery/subfinder")]
# outils en script, lancés par leur interpréteur : (nom, dépôt GitHub, lanceur)
SCRIPTS = [
    ("sqlmap", "sqlmapproject/sqlmap", [sys.executable, "sqlmap.py"]),
    ("nikto", "sullo/nikto", ["perl", "program/nikto.pl"]),
    ("testssl.sh", "testssl/testssl.sh", ["bash", "testssl.sh"]),
]
# outils lancés par Docker : (nom, image, options de docker run)
IMAGES = [("wpscan", "wpscanteam/wpscan", []),
          ("nmap", "instrumentisto/nmap", ["--network", "host"])]
ZAP_IMAGE = "zaproxy/zap-stable"
ZAP_CONTAINER = "bankai-zap"


def find(name):
    """L'outil téléchargé par `bankai setup` d'abord, sinon celui du système."""
    ours = BIN / name
    return str(ours) if ours.is_file() else shutil.which(name)


# ---------- téléchargement ----------

def fetch(url):
    r = requests.get(url, timeout=TIMEOUT, headers={"User-Agent": UA})
    r.raise_for_status()
    return r


def target():
    system = {"darwin": "macOS"}.get(platform.system().lower(), platform.system().lower())
    machine = platform.machine().lower()
    arch = {"x86_64": "amd64", "amd64": "amd64", "aarch64": "arm64", "arm64": "arm64",
            "i386": "386", "i686": "386"}.get(machine, machine)
    return system, arch


def write_wrapper(name, argv, cwd=None):
    BIN.mkdir(parents=True, exist_ok=True)
    cmd = " ".join(shlex.quote(a) for a in argv)
    cd = f"cd {shlex.quote(str(cwd))} && " if cwd else ""
    path = BIN / name
    path.write_text(f'#!/bin/sh\n{cd}exec {cmd} "$@"\n', encoding="utf-8")
    path.chmod(0o755)


def safe_members(tar, dest):
    root = dest.resolve()
    for m in tar.getmembers():
        if m.issym() or m.islnk() or m.isdev():
            continue
        if not (root / m.name).resolve().is_relative_to(root):
            raise RuntimeError(f"chemin suspect dans l'archive : {m.name}")
        yield m


def extract_tar(data, dest):
    tmp = dest.with_name(dest.name + ".tmp")
    shutil.rmtree(tmp, ignore_errors=True)
    tmp.mkdir(parents=True)
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tar:
        if hasattr(tarfile, "data_filter"):
            tar.extractall(tmp, filter="data")
        else:
            tar.extractall(tmp, members=list(safe_members(tar, tmp)))
    top = next(tmp.iterdir())  # l'archive GitHub contient un seul dossier <dépôt>-<branche>
    shutil.rmtree(dest, ignore_errors=True)
    top.rename(dest)
    shutil.rmtree(tmp, ignore_errors=True)


def install_release(name, repo):
    system, arch = target()
    release = fetch(f"https://api.github.com/repos/{repo}/releases/latest").json()
    suffix = f"_{system}_{arch}.zip"
    asset = next((a for a in release.get("assets", []) if a["name"].endswith(suffix)), None)
    if asset is None:
        raise RuntimeError(f"pas de version publiée pour {system}/{arch}")

    exe = name + (".exe" if system == "windows" else "")
    with zipfile.ZipFile(io.BytesIO(fetch(asset["browser_download_url"]).content)) as z:
        member = next((m for m in z.namelist() if Path(m).name == exe), None)
        if member is None:
            raise RuntimeError(f"{exe} absent de l'archive {asset['name']}")
        BIN.mkdir(parents=True, exist_ok=True)
        (BIN / name).write_bytes(z.read(member))
    (BIN / name).chmod(0o755)
    return release.get("tag_name", "")


def install_script(name, repo, launcher):
    interpreter = launcher[0]
    if not shutil.which(interpreter):
        raise RuntimeError(f"{Path(interpreter).name} introuvable sur cette machine")
    dest = SRC / name
    extract_tar(fetch(f"https://github.com/{repo}/archive/HEAD.tar.gz").content, dest)
    script = dest / launcher[1]
    if not script.is_file():
        raise RuntimeError(f"{launcher[1]} absent du dépôt {repo}")
    write_wrapper(name, [interpreter, str(script)], cwd=script.parent)
    return "dernière version"


def docker_ok():
    return bool(shutil.which("docker")) and subprocess.run(
        ["docker", "info"], capture_output=True).returncode == 0


def docker_pull(image):
    proc = subprocess.run(["docker", "pull", "-q", image], capture_output=True, text=True)
    if proc.returncode != 0:
        raise RuntimeError(proc.stderr.strip().splitlines()[-1] if proc.stderr.strip()
                           else f"docker pull {image} a échoué")


def install_image(name, image, options):
    if not docker_ok():
        raise RuntimeError("Docker introuvable ou arrêté")
    docker_pull(image)
    write_wrapper(name, ["docker", "run", "--rm", *options, image])
    return f"Docker : {image}"


# ---------- ZAP : démarré à la demande par le scan actif ----------

def zap_image_ready():
    return docker_ok() and subprocess.run(
        ["docker", "image", "inspect", ZAP_IMAGE], capture_output=True).returncode == 0


def start_zap(is_up, wait=180):
    """Lance ZAP dans Docker (accessible depuis cette machine seulement). Vrai si prêt."""
    if not zap_image_ready():
        return False
    subprocess.run(["docker", "rm", "-f", ZAP_CONTAINER], capture_output=True)
    proc = subprocess.run(
        ["docker", "run", "-d", "--rm", "--name", ZAP_CONTAINER, "-p", "127.0.0.1:8080:8080",
         ZAP_IMAGE, "zap.sh", "-daemon", "-host", "0.0.0.0", "-port", "8080",
         "-config", "api.addrs.addr.name=.*", "-config", "api.addrs.addr.regex=true",
         "-config", "api.disablekey=true"], capture_output=True)
    if proc.returncode != 0:
        return False
    deadline = time.time() + wait
    while time.time() < deadline:
        if is_up():
            return True
        time.sleep(3)
    stop_zap()
    return False


def stop_zap():
    subprocess.run(["docker", "stop", ZAP_CONTAINER], capture_output=True)


# ---------- la commande ----------

def setup(console):
    console.print(f"[bold red]卍[/] Installation des outils du scan actif dans [cyan]{HOME}[/]\n")
    ok = True

    def step(name, install):
        nonlocal ok
        found = shutil.which(name)
        if found and not (BIN / name).is_file():
            console.print(f"[green]✔[/] {name} [dim](déjà installé : {found})[/]")
            return
        with console.status(f"[bold]{name}[/] : téléchargement…"):
            try:
                detail = install()
            except (requests.RequestException, RuntimeError, OSError, zipfile.BadZipFile,
                    tarfile.TarError) as e:
                ok = False
                console.print(f"[red]✗[/] {name} : {e}")
                return
        console.print(f"[green]✔[/] {name} [dim]({detail})[/]")

    for name, repo in RELEASES:
        step(name, lambda name=name, repo=repo: install_release(name, repo))
    for name, repo, launcher in SCRIPTS:
        step(name, lambda name=name, repo=repo, launcher=launcher:
             install_script(name, repo, launcher))
    for name, image, options in IMAGES:
        step(name, lambda name=name, image=image, options=options:
             install_image(name, image, options))

    if zap_image_ready():
        console.print("[green]✔[/] zap [dim](image Docker déjà là)[/]")
    elif not docker_ok():
        ok = False
        console.print("[red]✗[/] zap : Docker introuvable ou arrêté")
    else:
        with console.status("[bold]zap[/] : téléchargement de l'image (environ 2,5 Go, ça peut être long)…"):
            try:
                docker_pull(ZAP_IMAGE)
                console.print("[green]✔[/] zap [dim](via Docker, démarré automatiquement pendant le scan)[/]")
            except RuntimeError as e:
                ok = False
                console.print(f"[red]✗[/] zap : {e}")

    console.print()
    if ok:
        console.print("[bold green]Tout est prêt.[/] Lance [bold]bankai[/] pour un audit complet.")
    else:
        console.print("[yellow]Certains outils manquent : le scan les sautera sans retirer de points. "
                      "Relance [bold]bankai setup[/] après avoir réglé le problème.[/]")
    return 0 if ok else 1
