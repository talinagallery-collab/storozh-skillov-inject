#!/usr/bin/env python3
"""Inject — первый слой проверки чужого решения на prompt-инъекции.

Только читает. Ничего не ставит, не удаляет, не переносит.
Значения ключей не печатает: в отчёте путь, строка и правило.

Вердикт (код выхода): 0 ЧИСТО · 1 ВОПРОСЫ · 2 СТОП · 3 ошибка запуска.

    inject_scan.py <папка или файл> [--json] [--no-gitleaks]
"""
import json
import os
import re
import shutil
import subprocess
import sys

STOP, ASK = "СТОП", "ВОПРОС"
MAX_BYTES = 2_000_000
SELF_DIR = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))


def is_self(path):
    """Папка самого Inject (её не проверяем: в правилах примеры опасного). Сравнение по
    границе папки: соседняя «inject-tools» — не мы и проверяется."""
    real = os.path.realpath(path)
    return real == SELF_DIR or real.startswith(SELF_DIR + os.sep)

# (уровень, правило, регулярка). Фразы собраны из частей, чтобы файл
# не ловил сам себя при проверке соседних папок.
_IGN = "ign" + "ore"
RULES = [
    # 1. Инструкция, которая перебивает наши правила
    (STOP, "перебивает-инструкции",
     rf"\b{_IGN}\s+(all\s+|any\s+)?(the\s+)?(previous|prior|above|earlier|system)\s+(instructions|prompts?|rules)"),
    (STOP, "перебивает-инструкции",
     r"\bdisregard\s+(all\s+|any\s+)?(the\s+)?(previous|prior|above|system)\s+(instructions|prompts?|rules)"),
    (STOP, "перебивает-инструкции",
     r"(игнорируй|забудь|отмени)\s+(все\s+)?(предыдущие|прежние|прошлые|системные)\s+(инструкции|указания|правила)"),
    (STOP, "подмена-роли", r"\b(new|updated)\s+system\s+prompt\b|\byou\s+are\s+now\s+(in\s+)?(developer|dan|jailbreak|unrestricted)"),
    (STOP, "скрыть-от-человека",
     r"\b(do\s+not|don'?t|never)\s+(tell|inform|mention|reveal|show)\s+(this\s+to\s+)?(the\s+)?(user|human|owner)(?!\s+to\b)"),
    (STOP, "скрыть-от-человека", r"не\s+(говори|сообщай|показывай|рассказывай)\s+(об\s+этом\s+)?(пользователю|человеку|владельцу)"),
    # 2. Скачать и сразу выполнить
    (STOP, "скачать-и-выполнить", r"\b(curl|wget)\b[^\n|]*(https?://|\$\{?\w)[^\n|]*(?<!\\)\|\s*(sudo\s+)?(ba|z)?sh\b"),
    (STOP, "скачать-и-выполнить", r"\b(curl|wget)\b[^\n|]*(https?://|\$\{?\w)[^\n|]*(?<!\\)\|\s*python3?(\s+-)?\s*($|[;&)])"),
    (STOP, "скачать-и-выполнить", r"base64\s+(-d|--decode)[^\n]*\|\s*(ba|z)?sh\b"),
    (STOP, "скачать-и-выполнить", r"\b(eval|exec)\s*\(\s*(base64|codecs\.decode|bytes\.fromhex|requests\.get|urllib)"),
    (STOP, "скачать-и-выполнить", r"\b(Invoke-Expression|iex)\s*\(|\bIEX\s*\(New-Object"),
    # 3. Отправка наружу
    (STOP, "отправка-наружу", r"webhook\.site|requestbin|pipedream\.net|interact\.sh|burpcollaborator|ngrok\.io|pastebin\.com/api"),
    (STOP, "отправка-наружу", r"discord(app)?\.com/api/webhooks"),
    (ASK, "отправка-наружу", r"\b(curl|wget)\b[^\n]*(\s-d\s|--data|\s-F\s|--form|--upload-file|-T\s|-X\s*POST)"),
    (ASK, "отправка-наружу", r"requests\.(post|put)\(|fetch\([^)]*method\s*:\s*['\"]POST|\bnc\s+-[a-z]*\s+\S+\s+\d+"),
    (ASK, "telegram-отправка", r"api\.telegram\.org/bot"),
    # 4. Чтение ключей и личного
    (ASK, "чтение-ключей", r"~/\.ssh|/\.ssh/|\bid_(rsa|ed25519|ecdsa)\b"),
    (ASK, "чтение-ключей", r"(^|[\s/'\"])\.env\b(?!\.example|\.sample)"),
    (ASK, "чтение-ключей", r"\bauth\.json\b|\.aws/credentials|\.netrc\b|\.git-credentials|\.npmrc\b|\.pypirc\b"),
    (ASK, "чтение-ключей", r"security\s+find-(generic|internet)-password|\bkeychain\b"),
    (ASK, "чтение-ключей", r"\bprintenv\b|os\.environ\.copy\(\)|\benv\s*>\s*\S"),
    # 5. Удаление и порча
    (STOP, "удаление", r"\brm\s+-[a-zA-Z]*r[a-zA-Z]*f?\s+(--no-preserve-root\s+)?(/|~|\$HOME)(\s|$|/\*)"),
    (ASK, "удаление", r"\brm\s+-[a-zA-Z]*[rf][a-zA-Z]*\b|shutil\.rmtree|\bunlink\s*\(|os\.remove\("),
    (ASK, "удаление", r"\bgit\s+push\s+(-f|--force)|\bgit\s+reset\s+--hard|\bmkfs\b|\bdd\s+if="),
    (ASK, "права", r"\bchmod\s+(-R\s+)?777\b|\bsudo\b"),
    # 6. Правка наших правил и автозапуска
    (ASK, "правка-правил", r"\b(CLAUDE|AGENTS|SOUL|MEMORY)\.md\b"),
    (ASK, "правка-правил", r"\.claude/settings(\.local)?\.json|\.codex/config\.toml|\bhooks?\b\s*[:=]"),
    (ASK, "автозапуск", r"LaunchAgents|LaunchDaemons|\bcrontab\b|launchctl\s+(load|bootstrap)|\.(zshrc|bashrc|bash_profile|zprofile)\b"),
    # 7. Скилл, который хочет срабатывать всегда
    (ASK, "срабатывает-всегда", r"^description:.*\b(always\s+use|use\s+(this\s+)?for\s+(any|every|all)\s+task|всегда\s+используй|для\s+любой\s+задачи)"),
]
RULES = [(lvl, name, re.compile(rx, re.IGNORECASE | re.MULTILINE)) for lvl, name, rx in RULES]

HIDDEN = re.compile("[​-‏‪-‮⁠-⁤⁦-⁩﻿\U000e0000-\U000e007f]")
LONG_BLOB = re.compile(r"[A-Za-z0-9+/=]{300,}")
TOKENISH = re.compile(r"[A-Za-z0-9_\-]{24,}")
SECRET_RULES = {"чтение-ключей"}
TEXT_EXT = {".md", ".txt", ".py", ".sh", ".bash", ".zsh", ".js", ".mjs", ".cjs", ".ts", ".json",
            ".yaml", ".yml", ".toml", ".ini", ".cfg", ".html", ".xml", ".ps1", ".rb", ".pl", ".env", ""}


def iter_files(target):
    if os.path.isfile(target):
        yield target
        return
    for root, dirs, files in os.walk(target, followlinks=False):
        dirs[:] = [d for d in dirs if d not in {".git", "node_modules", "__pycache__", ".venv"}]
        if is_self(root):
            continue
        for f in files:
            yield os.path.join(root, f)


def snippet(line, rule):
    if rule in SECRET_RULES:
        return ""
    s = TOKENISH.sub("…", line.strip())
    return s[:140]


def scan_file(path, findings, notes):
    try:
        if os.path.islink(path):
            notes.append({"path": path, "note": f"ссылка → {os.readlink(path)}"})
            return
        size = os.path.getsize(path)
        if size > MAX_BYTES:
            notes.append({"path": path, "note": f"большой файл {size} байт — не читал"})
            return
        with open(path, "rb") as fh:
            raw = fh.read()
    except OSError as e:
        notes.append({"path": path, "note": f"не прочитал: {e.strerror}"})
        return
    ext = os.path.splitext(path)[1].lower()
    if b"\x00" in raw[:4096]:
        lvl = ASK if os.access(path, os.X_OK) else None
        if lvl:
            findings.append({"level": ASK, "rule": "бинарник-исполняемый", "path": path, "line": 0, "text": ""})
        else:
            notes.append({"path": path, "note": "двоичный файл — не читал"})
        return
    text = raw.decode("utf-8", errors="replace")
    if text.startswith("﻿"):  # метка кодировки в начале файла — норма, не спрятанный текст
        text = text[1:]
    if ext not in TEXT_EXT and not text.startswith("#!"):
        notes.append({"path": path, "note": f"расширение {ext or '—'} — прочитал как текст"})
    lines = text.splitlines()
    before = len(findings)
    for i, line in enumerate(lines, 1):
        if HIDDEN.search(line):
            findings.append({"level": STOP, "rule": "невидимые-символы", "path": path, "line": i,
                             "text": HIDDEN.sub("⟨?⟩", line.strip())[:140]})
        if LONG_BLOB.search(line):
            findings.append({"level": ASK, "rule": "длинный-зашифрованный-кусок", "path": path, "line": i, "text": ""})
        for lvl, name, rx in RULES:
            if rx.search(line):
                findings.append({"level": lvl, "rule": name, "path": path, "line": i, "text": snippet(line, name)})
    rules_here = {f["rule"] for f in findings[before:]}
    if "чтение-ключей" in rules_here and "отправка-наружу" in rules_here:
        findings.append({"level": ASK, "rule": "ключи-и-отправка-в-одном-файле", "path": path, "line": 0, "text": ""})


def run_gitleaks(target):
    exe = shutil.which("gitleaks")
    if not exe:
        return None, "gitleaks не найден"
    try:
        p = subprocess.run([exe, "detect", "--no-git", "--redact", "--no-banner", "-s", target,
                            "--report-format", "json", "--report-path", "/dev/stdout", "--exit-code", "0"],
                           capture_output=True, text=True, timeout=120)
        out = p.stdout.strip()
        data = json.loads(out) if out.startswith("[") else []
        return [{"level": STOP, "rule": f"ключ:{d.get('RuleID')}", "path": d.get("File"),
                 "line": d.get("StartLine", 0), "text": ""} for d in data], None
    except Exception as e:  # noqa: BLE001
        return None, f"gitleaks не отработал: {e}"


def main(argv):
    args = [a for a in argv if not a.startswith("--")]
    if len(args) != 1 or not os.path.exists(args[0]):
        print(__doc__)
        return 3
    target = os.path.realpath(args[0])
    findings, notes = [], []
    files = 0
    for f in iter_files(target):
        files += 1
        scan_file(f, findings, notes)
    if "--no-gitleaks" not in argv:
        gl, err = run_gitleaks(target)
        if gl:
            findings.extend(gl)
        if err:
            notes.append({"path": target, "note": err})

    verdict = "ЧИСТО"
    if any(f["level"] == ASK for f in findings):
        verdict = "ВОПРОСЫ"
    if any(f["level"] == STOP for f in findings):
        verdict = "СТОП"
    code = {"ЧИСТО": 0, "ВОПРОСЫ": 1, "СТОП": 2}[verdict]

    if "--json" in argv:
        print(json.dumps({"target": target, "files": files, "verdict": verdict,
                          "findings": findings, "notes": notes}, ensure_ascii=False, indent=1))
        return code

    print(f"Inject · слой 1 · {target}")
    print(f"Файлов: {files} · вердикт: {verdict}")
    for lvl in (STOP, ASK):
        group = [f for f in findings if f["level"] == lvl]
        if not group:
            continue
        print(f"\n{lvl} ({len(group)}):")
        for f in group:
            rel = os.path.relpath(f["path"], target) if f["path"] and f["path"].startswith(target) else f["path"]
            tail = f" — {f['text']}" if f["text"] else ""
            print(f"  {rel}:{f['line']} [{f['rule']}]{tail}")
    if notes:
        print(f"\nЗаметки ({len(notes)}):")
        for n in notes[:30]:
            print(f"  {n['path']}: {n['note']}")
    print("\nСлой 1 ищет по шаблонам и не доказывает безопасность. Дальше — слой 2: прочитать самому.")
    return code


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
