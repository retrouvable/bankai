# 卍解 BANKAI

> Dans l'ombre, je construis. — Retrouvable

**Audit de sécurité de ton propre site, avec réparation automatique.**

BANKAI sonde ton site sans rien casser, lit son code, note sa sécurité de 0 à
100 (le **reiatsu**), puis écrit les correctifs directement dans ton code. Le
KILL façon Death Note : chaque faille dont le nom s'écrit dans le carnet est
**réparée**, jamais exploitée.

## Démarrage

```bash
pip install -e .
bankai setup   # une fois : télécharge les outils du scan actif
bankai
```

C'est tout : BANKAI te demande l'adresse de ton site et le dossier de son
code, puis te guide. Le scan actif est lancé à chaque fois ; `--quick` s'en
passe.

## Ce qui se passe

1. **Autorisation** : BANKAI vérifie que le code correspond au site (domaine
   ou nom du Worker trouvé dans le code) et te demande de confirmer qu'ils
   sont à toi. Il n'audite que ta propre infrastructure.
2. **斬 Sondes sur le site** : quelques requêtes GET, sans charge ni injection.
3. **記 Lecture du code** : rien n'est modifié à cette étape.
4. **Reiatsu** : la note de 0 à 100, la forme de ton épée et la liste des failles.
5. **卍解 Bankai** : si tu acceptes, le Death Note purifie les failles
   réparables et écrit les correctifs dans ton code.

## Ce qu'il trouve

| Sur le site | Dans le code |
|---|---|
| En-têtes de sécurité absents (CSP, HSTS, X-Frame-Options…) | Secrets écrits en dur (Discord, GitHub, Stripe, AWS, clés privées…) |
| En-têtes qui révèlent ta techno | `.env` commité dans git |
| Cookies sans Secure / HttpOnly / SameSite | `.gitignore` absent ou incomplet |
| CORS ouvert à tous | `eval()`, `new Function()`, `innerHTML`… |
| HTTP qui ne redirige pas vers HTTPS | |
| Fichiers sensibles publics (`.env`, `.git/`, `wrangler.toml`…) | |

## Ce qu'il écrit dans ton code

- **`bankai-shield.js`** : un bouclier pour ton Worker Cloudflare. Il ajoute
  les en-têtes de sécurité, force HTTPS et masque les en-têtes trop bavards.
  Sa CSP autorise les domaines que ta page utilise déjà, pour ne rien casser.
  Pour le brancher :

  ```js
  import { shield } from "./bankai-shield.js";
  export default { fetch: shield(async (request, env, ctx) => { /* ton code */ }) };
  ```

- **`.gitignore`** : complété pour que `.env` et compagnie ne partent jamais sur GitHub.
- **`SECURITY_AUDIT.md`** : le rapport, avec la liste de ce qu'il reste à corriger à la main.

Les secrets et le code risqué ne sont jamais modifiés automatiquement :
BANKAI t'indique où ils sont et comment les corriger.

## Les formes de l'épée

| Reiatsu | Forme | |
|---|---|---|
| 100 | 無間 Muken | Aucune faille. 計画通り. |
| 90+ | 卍解 Bankai | Redoutablement protégé |
| 75+ | 始解 Shikai | Il reste quelques Hollows |
| 50+ | 浅打 Asauchi | Des failles sérieuses |
| 25+ | 虚 Hollow | Beaucoup de failles |
| 0+ | 最下 Menos | Porte ouverte |

## 刃 Scan actif (par défaut)

En plus des sondes passives (headers, cookies, fichiers connus), BANKAI
lance une passe active : fuzzing de contenu (wordlist intégrée + seclists
si installé), XSS réfléchi, SSTI, path traversal/LFI, open redirect,
méthodes HTTP dangereuses (TRACE/PUT/DELETE), host header injection, JWT
`alg=none`, SQLi, et pilote ces outils :

| Outil | Rôle |
|---|---|
| `nuclei` | des milliers de CVE et mauvaises configs par templates |
| `nmap` | services et ports annexes exposés (DB, panel sur un autre port…) |
| `sqlmap` | injections SQL |
| `nikto` | fichiers par défaut, scripts oubliés, vieilles signatures serveur |
| `testssl.sh` | protocoles et chiffrements TLS, certificat |
| `wpscan` | plugins et thèmes WordPress vulnérables (si WordPress détecté) |
| `subfinder` | sous-domaines oubliés (staging, dev…) |
| OWASP ZAP | spider + scan actif, démarré et arrêté automatiquement |

`bankai setup` les télécharge depuis leurs sources officielles dans
`~/.local/share/bankai` (ou `$BANKAI_HOME`), sans rien installer sur le
système ni demander sudo. Ceux déjà présents sur la machine sont réutilisés.
Il faut Python, Perl et Bash pour sqlmap, nikto et testssl.sh, et Docker
pour wpscan, ZAP et nmap (si nmap n'est pas déjà installé). Chaque outil
garde sa propre licence. Un outil absent est sauté sans retirer de points.

```bash
bankai mon-site.com --repo . --details
bankai mon-site.com --repo . --no-zap --no-nmap  # sans ZAP ni nmap
bankai mon-site.com --repo . --quick             # sondes passives seulement
```

Toujours non destructif : pas d'écriture, pas de payload qui modifie de
donnée côté serveur, juste des sondes qui prouvent l'exploitabilité
(réflexion, erreur SQL, service identifié) sans l'exploiter réellement.

## Sans questions (scripts, CI)

```bash
bankai mon-site.com --repo . --yes --fix
```

| Option | Effet |
|---|---|
| `--repo` | le dossier du code du site |
| `--fix` | répare sans demander |
| `--yes` | aucune question (le site doit être à toi) |
| `--details` | montre la preuve et l'impact de chaque faille |
| `--quick` | sans le scan actif (plus rapide) |
| `--no-<outil>` | saute un outil : `nuclei`, `nmap`, `sqlmap`, `nikto`, `testssl`, `wpscan`, `subfinder`, `zap` |
| `--no-anim` | sans animation |

## Licence

MIT © Retrouvable
