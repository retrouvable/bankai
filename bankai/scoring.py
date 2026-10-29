from collections import namedtuple

Form = namedtuple("Form", "threshold kanji name color verdict")

FORMS = [
    Form(100, "無間", "MUKEN", "bright_white", "Aucune faille. 計画通り — tout se passe selon le plan."),
    Form(90, "卍解", "BANKAI", "green3", "Forme libérée. Le site est redoutablement protégé."),
    Form(75, "始解", "SHIKAI", "chartreuse3", "Lame éveillée. Il reste quelques Hollows."),
    Form(50, "浅打", "ASAUCHI", "gold1", "Lame nue. Des failles sérieuses à purifier."),
    Form(25, "虚", "HOLLOW", "dark_orange", "Corrompu. Beaucoup de failles exploitables."),
    Form(0, "最下", "MENOS", "red3", "État critique. Le site est une porte ouverte."),
]

RANKS = [(95, "S"), (85, "A"), (70, "B"), (50, "C"), (30, "D")]


def reiatsu(findings, with_shield=False):
    lost = sum(f.threat.cost for f in findings
               if not f.killed and not (with_shield and f.shielded))
    return max(0, 100 - lost)


def form(score):
    for f in FORMS:
        if score >= f.threshold:
            return f


def rank(score):
    for mini, letter in RANKS:
        if score >= mini:
            return letter
    return "F"
