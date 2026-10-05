#!/usr/bin/env python3
"""Сторож Inject: замечает новые и изменённые скиллы у Claude, Codex и агента на Hermes.

Новый скилл → проверка Inject → уведомление человеку (имя, чей, как вызвать,
вердикт) → пересборка единого списка. Изменённый скилл → уведомление, только
если проверка дала СТОП. Только читает папки скиллов; ничего не удаляет.

Состояние и журнал: ~/Library/Application Support/artais-inject/
Ищет SKILL.md по всему дому (кроме каталогов и копий — IGNORE в skills_registry).
Запуск — launchd com.artais.inject-watch: раз в 5 минут и при изменении главных папок.

    inject_watch.py [--state DIR] [--roots DIR ...] [--no-notify] [--no-registry]
"""
import datetime as dt
import json
import os
import re
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.realpath(__file__)))
import inject_scan  # noqa: E402
import skills_registry as reg  # noqa: E402

HOME = os.path.expanduser("~")
STATE_DIR = os.path.join(HOME, "Library/Application Support/artais-inject")


def classify(d):
    """Чей скилл и как вызвать — по месту в доме."""
    pairs = [
        (os.path.join(HOME, ".claude/skills/synced"), "Claude, из аккаунта claude.ai", "/anthropic-skills:{name}"),
        (os.path.join(HOME, ".claude/skills"), "Claude, глобальный", "/{name}"),
        (os.path.join(HOME, ".claude/plugins"), "Claude, из плагина", "/{name}"),
        (os.path.join(HOME, ".codex/skills"), "Codex, глобальный", "${name}"),
        (os.path.join(HOME, ".codex/plugins"), "Codex, из плагина", "${name}"),
        (os.path.join(HOME, ".vscode/extensions"), "расширение VS Code", "агенту в VS Code по смыслу"),
        (reg.LIN, "агент Hermes", "попроси агента Hermes: «скилл {name}»"),
    ]
    for prefix, who, how in pairs:
        if d.startswith(prefix + os.sep):
            return who, how
    if "/.claude/skills/" in d or "/.agents/skills/" in d:
        proj = re.split(r"/\.(?:claude|agents)/skills/", d)[0]
        return f"локальный, {reg.tilde(proj)}", "/{name} в чате, открытом в этой папке"
    return "другое место", "не подключён — черновик или копия"


def snapshot(test_roots=None):
    if test_roots:
        dirs = [d for r in test_roots for d in reg.skill_dirs(r, 4)]
    else:
        dirs = reg.discover_all()
    snap = {}
    for d in dirs:
        real = os.path.realpath(d)
        if real in snap:
            continue
        fm = reg.frontmatter(os.path.join(d, "SKILL.md"))
        name = fm.get("name") or os.path.basename(d)
        who, how = ("тест", "/{name}") if test_roots else classify(d)
        snap[real] = {"name": name, "who": who, "how": how.format(name=name),
                      "sha": reg.tree_sha(d), "where": reg.tilde(d)}
    return snap


def check(path):
    findings, notes = [], []
    if inject_scan.is_self(path):
        return "ЧИСТО", 0
    for f in inject_scan.iter_files(path):
        inject_scan.scan_file(f, findings, notes)
    gl, _ = inject_scan.run_gitleaks(path)
    findings += gl or []
    rv = reg.load_reviewed().get(reg.tree_sha(path)) if findings else None
    if rv:
        return f"прочитан: {rv['verdict']}", 0
    stops = sum(1 for x in findings if x["level"] == inject_scan.STOP)
    if stops:
        return "СТОП", stops
    return ("ВОПРОСЫ" if findings else "ЧИСТО"), 0


def notify(lines, alarm):
    """Окно посреди экрана — висит, пока человек не нажмёт «Понятно».
    Окно, а не баннер: баннеры легко пропустить или они выключены.
    Запускается отдельно и не держит сторожа."""
    def q(s):
        return s.replace("\\", "\\\\").replace('"', '\\"')
    if not lines:
        return
    shown = lines[:8] + ([f"…и ещё {len(lines) - 8} — в списке скиллов"] if len(lines) > 8 else [])
    title = "🔴 СТОП — не включать без проверки" if alarm else (
        "Новый скилл" if len(lines) == 1 else f"Новых скиллов: {len(lines)}")
    body = "\n\n".join(shown) + "\n\nСписок: " + reg.tilde(reg.OUT)
    kind = "critical" if alarm else "informational"
    script = (f'display alert "{q(title)}" message "{q(body)}" as {kind} '
              f'buttons {{"Понятно"}} default button 1 giving up after 86400')
    subprocess.Popen(["/usr/bin/osascript", "-e", script], stdout=subprocess.DEVNULL,
                     stderr=subprocess.DEVNULL, start_new_session=True)


def main(argv):
    state_dir = argv[argv.index("--state") + 1] if "--state" in argv else STATE_DIR
    if "--roots" in argv:
        i = argv.index("--roots") + 1
        test_roots = [r for r in argv[i:] if not r.startswith("--")]
    else:
        test_roots = None
    os.makedirs(state_dir, exist_ok=True)
    state_path = os.path.join(state_dir, "state.json")
    log_path = os.path.join(state_dir, "events.log")
    try:
        old = json.load(open(state_path, encoding="utf-8"))
    except (OSError, ValueError):
        old = {}
    first_run = "skills" not in old
    prev = old.get("skills", {})
    now = dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    snap = snapshot(test_roots)
    events = []
    for path, s in snap.items():
        before = prev.get(path)
        if first_run or (before and before["sha"] == s["sha"]):
            s["verdict"] = (before or {}).get("verdict", "—")
            continue
        verdict, stops = check(path)
        s["verdict"] = verdict
        kind = "новый" if not before else "изменён"
        events.append((kind, s, verdict, stops))
    for path, s in prev.items():
        if path not in snap:
            events.append(("убран", s, s.get("verdict", "—"), 0))

    news, alarms = [], []
    with open(log_path, "a", encoding="utf-8") as log:
        if first_run:
            log.write(f"{now}\tстарт\tзапомнил {len(snap)} скиллов\n")
        for kind, s, verdict, stops in events:
            log.write(f"{now}\t{kind}\t{s['name']}\t{s['who']}\t{verdict}\t{s['where']}\n")
            line = f"{s['name']} · {s['who']} · вызвать: {s['how']} · проверка: {verdict}"
            if verdict == "СТОП" and kind in ("новый", "изменён"):
                alarms.append(("изменён: " if kind == "изменён" else "") + line + f"\n{s['where']}")
            elif kind == "новый":
                news.append(line)
    if "--no-notify" not in argv:
        notify(alarms, True)
        notify(news, False)

    json.dump({"last_run": now, "skills": snap}, open(state_path, "w", encoding="utf-8"),
              ensure_ascii=False, indent=0)
    if (events or first_run) and "--no-registry" not in argv:
        try:
            reg.main([])
        except Exception as e:  # noqa: BLE001
            open(log_path, "a").write(f"{now}\tошибка списка\t{e}\n")
    print(f"{now} скиллов {len(snap)}, событий {len(events)}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
