import argparse
import sys

from rich.prompt import Prompt

from . import __version__, codebase, deep, fixes, tools, ui, web
from .models import BankaiError
from .scoring import reiatsu
from .target import ownership_hint, resolve_repo


def make_parser():
    p = argparse.ArgumentParser(
        prog="bankai",
        description="卍解 Audit de sécurité de ton propre site, avec réparation automatique.",
        epilog="Lancé sans argument, BANKAI pose les questions une par une. "
               "`bankai setup` installe les outils du scan actif.")
    p.add_argument("url", nargs="?", help="l'adresse de ton site")
    p.add_argument("-r", "--repo", help="le dossier du code du site")
    p.add_argument("--fix", action="store_true", help="réparer sans demander")
    p.add_argument("-y", "--yes", action="store_true", help="aucune question (le site doit être à toi)")
    p.add_argument("--details", action="store_true", help="montrer la preuve et l'impact de chaque faille")
    p.add_argument("--quick", action="store_true",
                   help="scan passif seulement, sans la passe active (plus rapide, aucun outil externe)")
    p.add_argument("--deep", action="store_true", help=argparse.SUPPRESS)  # actif par défaut désormais
    for tool in deep.ALL_TOOLS:
        p.add_argument(f"--no-{tool}", action="store_true", help=f"exclure {tool} du scan actif")
    p.add_argument("--no-anim", action="store_true", help="sans animation")
    p.add_argument("-V", "--version", action="version", version=f"BANKAI {__version__}")
    return p


def fill_missing(args, parser, tty):
    if args.url and args.repo:
        return
    if not tty:
        parser.error("il faut l'adresse du site et --repo (ou lance `bankai` seul dans un terminal)")
    if not args.url:
        args.url = Prompt.ask("[bold red]卍[/] Adresse de ton site", console=ui.console).strip()
    if not args.repo:
        args.repo = Prompt.ask("[bold red]卍[/] Dossier du code du site", default=".",
                               console=ui.console).strip()


def run(args, tty):
    ui.banner()
    url = args.url if "://" in args.url else "https://" + args.url
    repo = resolve_repo(args.repo)

    ui.authorization(url, repo, ownership_hint(repo, url))
    if not args.yes:
        if not tty:
            raise BankaiError("Impossible de te demander confirmation hors d'un terminal : "
                              "ajoute --yes si ce site est bien à toi.")
        if not ui.ask_yes("Ce site et ce code t'appartiennent ?", default=False):
            ui.console.print("[dim]Bankai scellé. Rien n'a été fait.[/]")
            return 1

    anim = tty and not args.no_anim
    ui.ichigo_charge(animate=anim)

    with ui.scanning("Sondes sur le site", "斬") as step:
        site = web.scan(url, step)
    ui.done("Sondes sur le site", "斬", len(site.findings))

    with ui.scanning("Lecture du code", "記") as step:
        code = codebase.scan(repo, step)
    ui.done("Lecture du code", "記", len(code))

    deep_findings = []
    if not args.quick:
        enabled = {t for t in deep.ALL_TOOLS if not getattr(args, f"no_{t}")}
        with ui.scanning("Scan actif (deep)", "刃") as step:
            deep_findings = deep.scan(url, step=step, tools=enabled)
        missing = [f for f in deep_findings if deep.missing_tool(f)]
        deep_findings = [f for f in deep_findings if not deep.missing_tool(f)]
        ui.done("Scan actif (deep)", "刃", len(deep_findings))
        ui.missing_tools(missing)

    ui.ichigo_release(animate=anim)

    findings = sorted(site.findings + code + deep_findings, key=lambda f: f.threat.cost, reverse=True)
    before = reiatsu(findings)
    ui.console.print()
    ui.console.print(ui.reiatsu_panel(before))
    if not findings:
        ui.closing(before)
        return 0

    ui.console.print(ui.findings_table(findings))
    if args.details:
        ui.details(findings)

    curable = [f for f in findings if f.auto]
    if not curable:
        ui.console.print("[dim]Aucune faille réparable automatiquement : suis les correctifs ci-dessus.[/]")
        return 0

    s = "s" if len(curable) > 1 else ""
    go = args.fix
    if not go and tty and not args.yes:
        go = ui.ask_yes(f"[bold red]卍解[/] Libérer le Bankai et purifier {len(curable)} faille{s} ?",
                        default=True)
    if not go:
        ui.console.print("[dim]Rien n'a été modifié. Relance avec --fix pour réparer.[/]")
        return 0

    ui.console.print()
    ui.light_laugh(animate=anim)
    ui.death_note(curable, animate=anim)
    written = fixes.apply(repo, site, findings, before)
    shield = reiatsu(findings, with_shield=True) if any(f.shielded for f in findings) else None
    ui.summary(before, reiatsu(findings), shield, written,
               [f for f in findings if not f.killed and not f.shielded])
    return 0


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if argv[:1] == ["setup"]:
        try:
            return tools.setup(ui.console)
        except KeyboardInterrupt:
            ui.console.print("\n[dim]Installation interrompue.[/]")
            return 130
    parser = make_parser()
    args = parser.parse_args(argv)
    tty = sys.stdin.isatty() and sys.stdout.isatty()
    try:
        fill_missing(args, parser, tty)
        return run(args, tty)
    except BankaiError as e:
        ui.error(str(e))
        return 1
    except KeyboardInterrupt:
        ui.console.print("\n[dim]Bankai scellé.[/]")
        return 130


if __name__ == "__main__":
    sys.exit(main())
