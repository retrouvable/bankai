from dataclasses import dataclass, field
from enum import Enum


class Threat(Enum):
    MENOS = ("Menos", 25, "white on red3", "critique")
    ADJUCHAS = ("Adjuchas", 12, "black on dark_orange", "élevée")
    GILLIAN = ("Gillian", 6, "black on gold1", "moyenne")
    HOLLOW = ("Hollow", 3, "black on cyan", "faible")
    MOD = ("Mod-soul", 1, "white on grey35", "info")

    def __init__(self, hollow, cost, badge, label):
        self.hollow = hollow
        self.cost = cost
        self.badge = badge
        self.label = label


class Fix(Enum):
    MANUAL = "manual"
    SHIELD = "shield"
    GITIGNORE = "gitignore"


@dataclass
class Finding:
    key: str
    title: str
    threat: Threat
    where: str
    evidence: str
    impact: str
    remedy: str
    fix: Fix = Fix.MANUAL
    killed: bool = False
    shielded: bool = False  # corrigée par bankai-shield.js, active une fois branché

    @property
    def auto(self):
        return self.fix != Fix.MANUAL


@dataclass
class SiteReport:
    findings: list = field(default_factory=list)
    script_hosts: set = field(default_factory=set)
    style_hosts: set = field(default_factory=set)
    font_hosts: set = field(default_factory=set)


class BankaiError(Exception):
    pass
