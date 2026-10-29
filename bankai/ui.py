import base64
import random
import time
import zlib
from contextlib import contextmanager

from rich import box
from rich.align import Align
from rich.columns import Columns
from rich.console import Console, Group
from rich.live import Live
from rich.markup import escape
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.prompt import Confirm, InvalidResponse
from rich.table import Table
from rich.text import Text

from .models import Fix
from .scoring import form, rank

console = Console(highlight=False)

BANNER = [
    "██████╗  █████╗ ███╗   ██╗██╗  ██╗ █████╗ ██╗",
    "██╔══██╗██╔══██╗████╗  ██║██║ ██╔╝██╔══██╗██║",
    "██████╔╝███████║██╔██╗ ██║█████╔╝ ███████║██║",
    "██╔══██╗██╔══██║██║╚██╗██║██╔═██╗ ██╔══██║██║",
    "██████╔╝██║  ██║██║ ╚████║██║  ██╗██║  ██║██║",
    "╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝",
]
COLORS = ["#ff5252", "#f03434", "#d91f1f", "#c01212", "#a30909", "#850404"]


class OuiNon(Confirm):
    choices = ["o", "n"]
    validate_error_message = "[prompt.invalid]Réponds o ou n"

    def process_response(self, value):
        v = value.strip().lower()
        if v in ("o", "oui", "y", "yes"):
            return True
        if v in ("n", "non", "no"):
            return False
        raise InvalidResponse(self.validate_error_message)


def ask_yes(question, default):
    return OuiNon.ask(question, default=default, console=console)


def banner():
    console.print()
    if console.width >= len(BANNER[0]) + 4:
        art = Text(no_wrap=True)
        for line, color in zip(BANNER, COLORS):
            art.append(line + "\n", style="bold " + color)
        console.print(Align.center(art))
    else:
        console.print(Align.center(Text("卍解  BANKAI", style="bold red")))
    console.print(Align.center(Text("卍解 · REIATSU SECURITY AUDIT", style="bold white")))
    console.print(Align.center(Text("Dans l'ombre, je construis. — Retrouvable", style="dim italic")))
    console.print()


def authorization(url, repo, hint):
    if hint:
        proof = f"[green]✔ {escape(hint)}[/]"
    else:
        proof = "[yellow]aucune trace du site dans le code — vérifie que c'est le bon repo[/]"
    console.print(Panel(
        f"[bold]Site[/]   {escape(url)}\n[bold]Code[/]   {escape(str(repo))}\n[bold]Lien[/]   {proof}",
        title="[bold]⚠ Autorisation[/]",
        subtitle="[dim]BANKAI n'audite que ta propre infrastructure[/]",
        border_style="yellow", padding=(1, 2)))


def _digit_spinner(style):
    # SpinnerColumn("dots") affiche des points Braille qui ressortent en carrés
    # sur une police qui ne les supporte pas : on les remplace par des chiffres.
    col = SpinnerColumn("dots", style=style)
    col.spinner.frames = list("0123456789")
    col.spinner.interval = 90
    return col


@contextmanager
def scanning(label, kanji):
    with Progress(_digit_spinner("bold red"),
                  TextColumn(f"[bold red]{kanji}[/] [bold]{label}[/]"),
                  TextColumn("[dim]{task.description}"),
                  console=console, transient=True) as progress:
        task = progress.add_task("")
        yield lambda what: progress.update(task, description=escape(what))


def done(label, kanji, n):
    s = "s" if n > 1 else ""
    console.print(f"[green]✔[/] [bold red]{kanji}[/] [bold]{label}[/] [dim]— {n} faille{s} trouvée{s}[/]")


# ---------- animation : Ichigo, le Getsuga Tenshō ----------
# scène originale (silhouette + vague d'énergie sous la lune) composée par
# programme et rendue en demi-blocs couleur 24 bits. Les pixels bruts (RGB,
# compressés) sont dans bankai/ichigo_art.py ; on les décode en texte ANSI
# ici, à l'affichage, pour ne pas stocker de longues chaînes toutes faites.

def _decompress(mod):
    """Décompresse les pixels bruts (RGB) stockés dans un module *_art généré."""
    try:
        return zlib.decompress(base64.b64decode(mod.DATA))
    except Exception:  # pragma: no cover - l'asset peut être absent/corrompu
        return b""


def _pixels_to_rows(buf, w, h):
    """RGB brut (demi-bloc ▀ : fg = pixel haut, bg = pixel bas) -> lignes ANSI."""
    rows = []
    for y in range(0, h, 2):
        parts = []
        for x in range(w):
            i_top = (y * w + x) * 3
            i_bot = ((y + 1) * w + x) * 3
            tr, tg, tb = buf[i_top:i_top + 3]
            br, bg, bb = buf[i_bot:i_bot + 3]
            parts.append(f"\x1b[38;2;{tr};{tg};{tb};48;2;{br};{bg};{bb}m▀")
        parts.append("\x1b[0m")
        rows.append("".join(parts))
    return rows


def _frame_at(raw, mod, n):
    """La frame n d'un module *_art (W, H, N_FRAMES, DELAYS, DATA), en lignes ANSI."""
    size = mod.W * mod.H * 3
    return _pixels_to_rows(raw[n * size:(n + 1) * size], mod.W, mod.H)


try:
    from . import ichigo_art
    _ICHIGO_RAW = _decompress(ichigo_art)
except Exception:  # pragma: no cover - l'asset peut être absent
    ichigo_art = None
    _ICHIGO_RAW = b""


def _block(art, style):
    """Un art ASCII (lignes de longueurs différentes) comme UN seul bloc centré,
    pour que les lignes restent alignées entre elles (sinon chacune se centre
    toute seule sur la largeur du terminal et la silhouette part en vrac)."""
    width = max(len(l) for l in art)
    text = Text("\n".join(l.center(width) for l in art), style=style, justify="center")
    return Align.center(text)


def _ichigo_frame(n):
    return _frame_at(_ICHIGO_RAW, ichigo_art, n)


def _ansi_block(rows):
    """Rend des lignes ANSI (demi-blocs couleur) comme un bloc centré."""
    return Group(*(Align.center(Text.from_ansi(r)) for r in rows))


# dans ichigo_art.py : frames 0-7 = charge du reiatsu (posture, aura, étincelles),
# frames 8-23 = coup de sabre puis le Getsuga qui jaillit. On coupe la séquence
# en deux pour jouer la charge avant le scan et le lâcher après, comme demandé.
_ICHIGO_STRIKE_START = 8


def ichigo_charge(animate=True):
    """Ichigo charge son reiatsu, juste avant le scan."""
    if not _ICHIGO_RAW or not animate or console.width < ichigo_art.W:
        console.print(Align.center(Text("斬月 — la pression monte...", style="bold red")))
        console.print()
        return

    first = _ichigo_frame(0)
    with Live(console=console, refresh_per_second=30, transient=True) as live:
        # la scène se révèle du haut vers le bas
        for n in range(1, len(first) + 1):
            live.update(_ansi_block(first[:n]))
            time.sleep(0.04)
        time.sleep(0.4)
        # la posture se creuse, l'aura et les étincelles montent
        for n in range(1, _ICHIGO_STRIKE_START):
            live.update(_ansi_block(_ichigo_frame(n)))
            time.sleep(ichigo_art.DELAYS[n])
        time.sleep(0.4)
    console.print()


def ichigo_release(animate=True):
    """Ichigo termine son geste : coup de sabre, puis le Getsuga Tenshō jaillit."""
    if not _ICHIGO_RAW or not animate or console.width < ichigo_art.W:
        console.print(Align.center(Text("斬月 — 月牙天衝 · GETSUGA TENSHŌ", style="bold red")))
        console.print()
        return

    caption = Group(
        Text(),
        Align.center(Text("月 牙 天 衝", style="bold red")),
        Align.center(Text("G E T S U G A   T E N S H Ō", style="bold white")),
    )
    last = ichigo_art.N_FRAMES - 1
    with Live(console=console, refresh_per_second=30, transient=True) as live:
        for n in range(_ICHIGO_STRIKE_START, ichigo_art.N_FRAMES):
            live.update(_ansi_block(_ichigo_frame(n)))
            time.sleep(ichigo_art.DELAYS[n])
        # apogée tenue + nom de l'attaque
        live.update(Group(_ansi_block(_ichigo_frame(last)), caption))
        time.sleep(2.0)
    console.print()


def reiatsu_panel(score, title="Pression spirituelle"):
    f = form(score)
    width = 30
    full = round(width * score / 100)
    bar = Text("━" * full, style="bold " + f.color) + Text("━" * (width - full), style="grey23")
    score_line = Text.assemble((str(score), "bold " + f.color), ("/100", "dim"),
                               "   rang ", (rank(score), "bold " + f.color))
    body = Group(
        Align.center(Text(f"{f.kanji}  {f.name}", style="bold " + f.color)),
        Text(),
        Align.center(bar),
        Align.center(score_line),
        Text(),
        Align.center(Text(f.verdict, style="italic dim")),
    )
    return Panel(body, title=f"[bold]卍 {title}[/]", border_style=f.color, padding=(1, 2))


def findings_table(findings):
    t = Table(box=box.SIMPLE_HEAD, expand=True, show_edge=False, header_style="bold")
    t.add_column("Menace", no_wrap=True)
    t.add_column("Faille", ratio=3)
    t.add_column("Correctif", ratio=3, style="dim")
    t.add_column("", justify="center", no_wrap=True)

    for f in findings:
        t.add_row(Text(f" {f.threat.label.upper()} ", style=f.threat.badge),
                  Text.assemble((f.title, "bold"), "\n", (f.where, "cyan")),
                  f.remedy,
                  Text("卍", style="bold red") if f.auto else Text("✋"))

    s = "s" if len(findings) > 1 else ""
    return Panel(t, title=f"[bold]虚 {len(findings)} Hollow{s} détecté{s}[/]",
                 subtitle="[dim]卍 réparable automatiquement · ✋ à corriger à la main[/]",
                 border_style="red", padding=(1, 1))


def details(findings):
    for f in findings:
        console.print(Panel(
            f"[bold]Preuve[/]     {escape(f.evidence)}\n"
            f"[bold]Impact[/]     {escape(f.impact)}\n"
            f"[bold green]Correctif[/]  {escape(f.remedy)}",
            title=f"[{f.threat.badge}] {f.threat.label.upper()} [/] [bold]{escape(f.title)}[/]",
            title_align="left", subtitle=f"[cyan]{escape(f.where)}[/]", subtitle_align="left",
            border_style="grey42", padding=(0, 2)))


# ---------- animation : Light, le rire puis le carnet qui descend ----------
# portrait réaliste : la scène du rire (demi-blocs couleur 24 bits) générée
# depuis l'image fournie par l'utilisateur -> bankai/light_art.py. Pas de
# dépendance au runtime, les lignes sont des chaînes ANSI pré-calculées.

try:
    from .light_art import LIGHT_ROWS
except Exception:  # pragma: no cover - l'asset peut être absent
    LIGHT_ROWS = []

_LIGHT_W = max((len(Text.from_ansi(r).plain) for r in LIGHT_ROWS), default=0)


def _light_block(rows, dim=False):
    """Rend les lignes ANSI de Light comme un bloc centré."""
    style = "dim" if dim else ""
    return Group(*(Align.center(Text.from_ansi(r, style=style)) for r in rows))


# le carnet : zoom sur sa couverture, qui s'ouvre ensuite lentement sur les
# pages -> bankai/notebook_art.py (même principe que Ichigo : pixels bruts).

try:
    from . import notebook_art
    _NOTEBOOK_RAW = _decompress(notebook_art)
except Exception:  # pragma: no cover - l'asset peut être absent
    notebook_art = None
    _NOTEBOOK_RAW = b""


def _notebook_frame(n):
    return _frame_at(_NOTEBOOK_RAW, notebook_art, n)


def light_laugh(animate=True):
    """Light apparaît, rit — juste avant que BANKAI ne purifie les failles."""
    if not LIGHT_ROWS or not animate or console.width < _LIGHT_W:
        console.print(Align.center(Text('Kukukuku... "Tout se déroule comme prévu."',
                                        style="bold italic")))
        console.print()
        return

    caption = Group(
        Text(),
        Align.center(Text("Kukukuku...", style="bold red")),
        Align.center(Text('"Tout se déroule comme prévu."', style="dim italic")),
    )

    with Live(console=console, refresh_per_second=30, transient=True) as live:
        # apparition : l'image se révèle du haut vers le bas
        for n in range(1, len(LIGHT_ROWS) + 1):
            live.update(_light_block(LIGHT_ROWS[:n]))
            time.sleep(0.045)
        time.sleep(0.6)

        # il rit : léger tremblement (l'image monte/descend d'une ligne)
        blank = Text("")
        for _ in range(5):
            live.update(Group(blank, _light_block(LIGHT_ROWS), caption))
            time.sleep(0.12)
            live.update(Group(_light_block(LIGHT_ROWS), blank, caption))
            time.sleep(0.12)

        live.update(Group(_light_block(LIGHT_ROWS), caption))
        time.sleep(2.2)
    console.print()


def _notebook_fall(live):
    """Zoom sur la couverture du carnet, qui s'ouvre ensuite lentement sur les pages."""
    if not _NOTEBOOK_RAW or console.width < notebook_art.W:
        live.update(Align.center(Text("死 DEATH NOTE", style="bold white")))
        time.sleep(0.6)
        return
    for n, delay in zip(range(notebook_art.N_FRAMES), notebook_art.DELAYS):
        live.update(_ansi_block(_notebook_frame(n)))
        time.sleep(delay)
    time.sleep(0.3)


def death_note(findings, animate):
    lines = []
    rule = Text("Toute faille dont le nom est écrit dans ce carnet sera corrigée.",
                style="dim italic", justify="center")

    def page(writing=None):
        rows = lines + [writing] if writing else lines
        return Panel(Group(rule, Text(), *rows), title="[bold white]死 DEATH NOTE[/]",
                     border_style="grey50", padding=(1, 3))

    def crossed(i, f):
        verdict = ("🛡 bouclier prêt", "bold cyan") if f.fix == Fix.SHIELD else ("☠ purifiée", "bold green")
        return Text.assemble((f"{i:>2}. ", "dim"), (f.title, "strike red"), "   ", verdict)

    if not animate:
        lines += [crossed(i, f) for i, f in enumerate(findings, 1)]
        console.print(page())
        return

    with Live(Text(""), console=console, refresh_per_second=60) as live:
        _notebook_fall(live)
        live.update(page())
        time.sleep(0.2)
        for i, f in enumerate(findings, 1):
            for n in range(1, len(f.title) + 1):
                live.update(page(Text.assemble((f"{i:>2}. ", "dim"), (f.title[:n], "bold white"),
                                               ("▌", "red"))))
                time.sleep(0.02)
            time.sleep(0.3)
            lines.append(crossed(i, f))
            live.update(page())
            time.sleep(0.2)


def summary(before, after, shield, written, left):
    panels = [reiatsu_panel(before, "Avant"), reiatsu_panel(after, "Maintenant")]
    if shield is not None:
        panels.append(reiatsu_panel(shield, "Bouclier branché"))
    console.print(Columns(panels, equal=True, expand=True))
    console.print(Panel("\n".join(f"[green]✔[/] {escape(w)}" for w in written),
                        title="[bold]記 Écrit dans ton code[/]", border_style="green", padding=(1, 2)))
    todo = [f"[yellow]✋[/] [bold]{escape(f.title)}[/] [cyan]{escape(f.where)}[/]\n"
            f"   [dim]{escape(f.remedy)}[/]" for f in left]
    if shield is not None:
        todo.insert(0, "[yellow]✋[/] [bold]Brancher bankai-shield.js dans ton Worker[/]\n"
                       "   [dim]Tant que ce n'est pas fait, les en-têtes et la redirection HTTPS "
                       "ne sont pas actifs (voir le README).[/]")
    if todo:
        console.print(Panel("\n".join(todo), title="[bold]À faire à la main[/]",
                            border_style="yellow", padding=(1, 2)))
    closing(after)


def closing(score):
    if score >= 90:
        quote = "計画通り — tout se passe selon le plan."
    else:
        quote = "Le combat continue. Corrige le reste, puis relance BANKAI."
    console.print(Align.center(Text(quote, style="bold italic red")))
    console.print()


def missing_tools(findings):
    if not findings:
        return
    lines = [f"[dim]·[/] {escape(f.title)}" for f in findings]
    console.print(Panel("\n".join(lines), title="[bold]Outils absents (aucun point retiré)[/]",
                        subtitle="[dim]bankai setup installe ce qui manque[/]",
                        border_style="grey42", padding=(0, 2)))


def error(msg):
    console.print(Panel(escape(msg), title="[bold]✗ Bankai interrompu[/]",
                        border_style="red", padding=(1, 2)))
