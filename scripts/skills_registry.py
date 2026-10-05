#!/usr/bin/env python3
"""Единый список скиллов всех агентов: скилл — коротко — кто поставил — когда — где.

Только читает папки скиллов; пишет один файл списка. Для каждого скилла
запускает слой 1 Inject (без gitleaks) и ставит вердикт.

    skills_registry.py [путь-к-списку]
"""
import datetime as dt
import json
import os
import re
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.realpath(__file__)))
import inject_scan  # noqa: E402

HOME = os.path.expanduser("~")
PROJECTS = os.environ.get("INJECT_PROJECTS", os.path.join(HOME, "Documents/projects"))
LIN = os.environ.get("INJECT_HERMES_SKILLS", os.path.join(HOME, ".hermes/skills"))
OUT = os.environ.get("INJECT_REGISTRY", os.path.join(PROJECTS, "REESTR-SKILLOV.md"))


def frontmatter(path):
    try:
        text = open(path, encoding="utf-8", errors="replace").read(8000)
    except OSError:
        return {}
    m = re.match(r"^﻿?---\s*\n(.*?)\n---", text, re.S)
    if not m:
        return {}
    fm, key = {}, None
    for line in m.group(1).splitlines():
        km = re.match(r"^([A-Za-z_]+):\s*(.*)$", line)
        if km:
            key, val = km.group(1), km.group(2).strip().strip("\"'")
            fm[key] = val
        elif key and line.startswith((" ", "\t")):
            fm[key] = (fm[key] + " " + line.strip()).strip()
    return fm


def short(desc):
    d = desc.strip().strip("\"'>|").strip()
    d = re.split(r"(?<=[.!?])\s", d, maxsplit=1)[0]
    return (d[:110] + "…") if len(d) > 110 else d


def born(path):
    try:
        st = os.lstat(path)
        ts = getattr(st, "st_birthtime", st.st_mtime)
        return dt.datetime.fromtimestamp(ts).strftime("%d.%m.%Y")
    except OSError:
        return "—"


def tilde(p):
    if p.startswith(LIN):
        return "Hermes/skills" + p[len(LIN):]
    p = re.sub(r"/synced/[0-9a-f_-]{40,}/", "/synced/…/", p)
    return p.replace(HOME, "~", 1)


REVIEWED = os.path.join(os.path.dirname(os.path.dirname(os.path.realpath(__file__))), "reviewed.json")


def tree_sha(skill_dir):
    import hashlib
    h = hashlib.sha256()
    for f in sorted(inject_scan.iter_files(os.path.realpath(skill_dir))):
        try:
            h.update(os.path.relpath(f, skill_dir).encode())
            h.update(open(f, "rb").read())
        except OSError:
            pass
    return h.hexdigest()


def load_reviewed():
    try:
        return json.load(open(REVIEWED, encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def verdict(skill_dir):
    findings, notes = [], []
    if inject_scan.is_self(skill_dir):
        return "— (сам Inject)"
    for f in inject_scan.iter_files(os.path.realpath(skill_dir)):
        inject_scan.scan_file(f, findings, notes)
    if findings:
        rv = load_reviewed().get(tree_sha(skill_dir))
        if rv:
            return f"{rv.get('mark', '🟢')} прочитан {rv['date']}: {rv['verdict']}"
    if any(x["level"] == inject_scan.STOP for x in findings):
        return "🔴 СТОП"
    if findings:
        return "🟡 вопросы"
    return "🟢 чисто"


def skill_dirs(root, max_depth):
    if not os.path.isdir(root):
        return
    root_depth = root.rstrip("/").count("/")
    for cur, dirs, files in os.walk(root, followlinks=True):
        dirs[:] = sorted(d for d in dirs if not d.startswith(".") or d == ".system")
        if cur.count("/") - root_depth > max_depth:
            dirs[:] = []
            continue
        if "SKILL.md" in files:
            dirs[:] = []
            yield cur


def row(skill_dir, who, how, when=None):
    fm = frontmatter(os.path.join(skill_dir, "SKILL.md"))
    name = fm.get("name") or os.path.basename(skill_dir)
    author = fm.get("author") or ""
    return {
        "name": name,
        "short": short(fm.get("description", "")) or "—",
        "who": who if not author else f"{who}; автор: {author}",
        "when": when or born(skill_dir),
        "where": tilde(skill_dir),
        "how": how.format(name=name),
        "check": verdict(skill_dir),
        "_real": os.path.realpath(skill_dir),
    }


# Каталоги магазинов, исходники, тестовые и резервные копии — агенты их не подхватывают
IGNORE = [
    os.path.join(HOME, ".claude/plugins/marketplaces"),
    os.path.join(HOME, ".codex/.tmp"),
    os.path.join(HOME, ".Trash"),
    os.path.join(HOME, ".claude/skills/.trash"),
]
IGNORE_WORDS = ("BACKUP",)
# Не заходить: защищённые macOS места (иначе мак спрашивает доступ к медиатеке, фото
# и т.п.) и папки, где активных скиллов не бывает — только копии и загрузки.
PRUNE = ["Library", ".Trash", "Pictures", "Movies", "Music", "Desktop", "Downloads",
         "Yandex.Disk.localized", "Public"]


def ignored(path):
    return any(path.startswith(p) for p in IGNORE) or any(w in path for w in IGNORE_WORDS)


def discover_all():
    """Все папки с SKILL.md во всём доме, кроме каталогов и копий. ~1 с."""
    expr = []
    for p in PRUNE:
        expr += ["-path", os.path.join(HOME, p), "-o"]
    cmd = ["/usr/bin/find", HOME, "("] + expr + ["-name", "node_modules", "-o", "-name", ".git", ")",
                                                 "-prune", "-o", "-name", "SKILL.md", "-print"]
    out = subprocess.run(cmd, capture_output=True, text=True, timeout=120).stdout
    dirs = {os.path.dirname(line) for line in out.splitlines() if line}
    return sorted(d for d in dirs if not ignored(d))


def collect():
    groups = []

    # Claude — глобальные
    rows = []
    base = os.path.join(HOME, ".claude/skills")
    for d in skill_dirs(base, 3):
        rel = os.path.relpath(d, base)
        top = os.path.join(base, rel.split(os.sep)[0])
        if rel.startswith("synced"):
            who, when = "аккаунт claude.ai (Anthropic), синхронизация", born(d)
        elif os.path.islink(top):
            who, when = f"наш, ссылка на {tilde(os.path.realpath(top))}", born(top)
        else:
            who, when = "не записано", born(d)
        how = "/anthropic-skills:{name} в любом чате Claude" if rel.startswith("synced") else "/{name} в любом чате Claude"
        rows.append(row(d, who, how, when))
    groups.append(("Claude — глобальные (`~/.claude/skills`), работают в любой папке", rows))

    # Claude — локальные в проектах
    rows = []
    proj_roots = [os.path.join(PROJECTS, ".claude/skills")] + [
        os.path.join(PROJECTS, t, ".claude/skills") for t in (sorted(os.listdir(PROJECTS)) if os.path.isdir(PROJECTS) else [])
        if os.path.isdir(os.path.join(PROJECTS, t, ".claude/skills"))]
    for pr in proj_roots:
        for d in skill_dirs(pr, 2):
            proj = tilde(os.path.dirname(os.path.dirname(pr)))
            link = os.path.join(pr, os.path.relpath(d, pr).split(os.sep)[0])
            who = "наш (папка .agents/skills)" if os.path.islink(link) else "не записано"
            rows.append(row(d, who, f"/{{name}} — только в чате, открытом в {proj}", born(link)))
    groups.append(("Claude — локальные, только в своей папке проекта", rows))

    # Codex
    rows = []
    base = os.path.join(HOME, ".codex/skills")
    for d in skill_dirs(base, 3):
        rel = os.path.relpath(d, base)
        top = os.path.join(base, rel.split(os.sep)[0])
        if rel.startswith(".system"):
            who = "Codex (OpenAI), системный"
        elif os.path.islink(top):
            who = f"наш, ссылка на {tilde(os.path.realpath(top))}"
        else:
            who = "не записано"
        rows.append(row(d, who, "${name} в Codex (не проверено на нашей версии)", born(top)))
    groups.append(("Codex — глобальные (`~/.codex/skills`)", rows))

    # Агент на Hermes
    bundled = set()
    try:
        bundled = {ln.split(":")[0].strip() for ln in open(os.path.join(LIN, ".bundled_manifest")) if ":" in ln}
    except OSError:
        pass
    usage = {}
    try:
        usage = json.load(open(os.path.join(LIN, ".usage.json")))
    except (OSError, ValueError):
        pass
    own, kit = [], []
    for d in skill_dirs(LIN, 3):
        fm = frontmatter(os.path.join(d, "SKILL.md"))
        name = fm.get("name") or os.path.basename(d)
        u = usage.get(name) or usage.get(os.path.basename(d)) or {}
        when = (u.get("created_at") or "")[:10]
        when = dt.date.fromisoformat(when).strftime("%d.%m.%Y") if when else born(d)
        if name in bundled or os.path.basename(d) in bundled:
            kit.append(row(d, "Hermes — пришёл с ним при установке", "попроси агента Hermes: «скилл {name}»", when))
        else:
            who = "агент сам" + (f" ({u['created_by']})" if u.get("created_by") else "")
            own.append(row(d, who, "попроси агента Hermes: «скилл {name}»", when))
    groups.append(("Агент Hermes — свои (сделал или поставил сам)", own))
    groups.append(("Агент Hermes — из набора Hermes", kit))

    # Всё остальное во всём доме
    covered = {r["_real"] for _, rs in groups for r in rs}
    codex_pl, vscode, other = [], [], []
    cpl = os.path.join(HOME, ".codex/plugins/cache") + os.sep
    vsc = os.path.join(HOME, ".vscode/extensions") + os.sep
    for d in discover_all():
        if os.path.realpath(d) in covered:
            continue
        if d.startswith(cpl):
            plugin = "/".join(os.path.relpath(d, cpl).split(os.sep)[:2])
            codex_pl.append(row(d, f"плагин Codex `{plugin}`", "${name} в Codex"))
        elif d.startswith(vsc):
            ext = os.path.relpath(d, vsc).split(os.sep)[0]
            vscode.append(row(d, f"расширение VS Code `{ext}`", "агенту в VS Code — по смыслу"))
        else:
            proj = d.split("/.claude/skills/")[0] if "/.claude/skills/" in d else None
            how = f"/{{name}} — в чате, открытом в {tilde(proj)}" if proj else "не подключён ни к одному агенту — черновик или копия"
            other.append(row(d, "не записано", how))
    groups.append(("Codex — из установленных плагинов (`~/.codex/plugins`)", codex_pl))
    groups.append(("VS Code — внутри расширений (`~/.vscode/extensions`)", vscode))
    groups.append(("Другие места в доме", other))
    return groups


def render(groups):
    now = dt.datetime.now().strftime("%d.%m.%Y %H:%M")
    total = sum(len(r) for _, r in groups)
    stop = sum(1 for _, rs in groups for r in rs if "СТОП" in r["check"])
    out = [
        "# Единый список скиллов",
        "",
        f"Собран автоматически {now} — `.agents/skills/inject/scripts/skills_registry.py`. Руками не править: "
        "перезапишется. Всего {total}; 🔴 СТОП — {stop}.".format(total=total, stop=stop),
        "",
        "Проверка — слой 1 Inject (по шаблонам). 🟡 «вопросы» почти всегда норма (скилл читает свой ключ, "
        "шлёт в Telegram); 🔴 СТОП — не включать, пока не прочитан человеком. Забыла имя — ищи здесь по слову "
        "или спроси агента: «был скилл про …, найди».",
        "",
    ]
    for title, rows in groups:
        out += [f"## {title} — {len(rows)}", ""]
        if not rows:
            out += ["Нет.", ""]
            continue
        out += ["| Скилл | Коротко | Кто поставил | Когда | Где искать | Как вызвать | Проверка |",
                "|---|---|---|---|---|---|---|"]
        for r in sorted(rows, key=lambda r: r["name"].lower()):
            cells = [f"**{r['name']}**", r["short"], r["who"], r["when"], f"`{r['where']}`", r["how"], r["check"]]
            out.append("| " + " | ".join(c.replace("|", "\\|") for c in cells) + " |")
        out.append("")
    out += ["Не входят — агенты их не подхватывают: каталоги магазинов (`~/.claude/plugins/marketplaces`, "
            "`~/.codex/.tmp/plugins`), резервные копии (`BACKUP`), Корзина. Список мест — `IGNORE` в сборщике.", ""]
    return "\n".join(out)


def main(argv):
    out = argv[0] if argv else OUT
    groups = collect()
    text = render(groups)
    with open(out, "w", encoding="utf-8") as fh:
        fh.write(text)
    for title, rows in groups:
        print(f"{len(rows):4}  {title}")
    print("→", out)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
