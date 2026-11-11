# Copyright (c) 2026 A Simple Block. Auto-Modpacker.
# Source-available, noncommercial use only. No commercial use and no use by
# Excluded Parties without the author's written permission. Credit required.
# See LICENSE.md and EXCLUDED.md in the project repository.
import zipfile
import io
import os
import re
import json
import time
import shutil
import textwrap
import html as html_esc
import hashlib
import datetime
import urllib.request
import urllib.error
import urllib.parse
import ast
import builtins
import types
import sys
import zlib
import http.client

try:
    import tomllib
except ImportError:
    tomllib = None

RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
BOLD = "\033[1m"
DIM = "\033[2m"
RESET = "\033[0m"

CACHE_TTL_SECONDS = 7 * 24 * 3600  # неделя

ANSI_RE = re.compile(r"\033\[[0-9;]*m")

def strip_ansi(text):
    return ANSI_RE.sub("", text)

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
LOGS_DIR = os.path.join(SCRIPT_DIR, "script_logs")
CONSOLE_DIR = os.path.join(SCRIPT_DIR, "console_output")
TIMELINE_DIR = os.path.join(SCRIPT_DIR, "timeline")
CACHE_PATH = os.path.join(SCRIPT_DIR, ".auto_modpacker_cache.json")
# c001
CF_KEY_PATH = os.path.join(SCRIPT_DIR, "CurseForgeApiKey_DO_NOT_SHARE.txt")
CF_KEY_HEADER = "# Ключ CurseForge API — конфиденциальные данные. Не передавайте этот файл другим лицам.\n"

IMPLICIT = {"minecraft", "neoforge", "forge", "java", "fabricloader"}
NATIVE_LIB_EXT = (".dll", ".so", ".dylib")
EXEC_EXT = (".exe", ".bat", ".cmd")
POWERSHELL_EXT = (".ps1",)
NETWORK_SIGNATURES = [  # c006
    (b"io/netty", "Netty"),
    (b"java/net/Socket", "java.net.Socket"),
    (b"java/net/http", "java.net.http"),
    (b"java/net/URL", "java.net.URL"),
    (b"javax/net/ssl", "javax.net.ssl"),
    (b"WebSocket", "WebSocket"),
    (b"okhttp3", "OkHttp"),
]
DYNAMIC_LOAD_SIGNATURES = [
    (b"Class.forName", "Class.forName"),
    (b"defineClass", "ClassLoader.defineClass"),
    (b"URLClassLoader", "URLClassLoader"),
]
SEVERITY_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
SEVERITY_COLOR = {"HIGH": RED, "MEDIUM": YELLOW, "LOW": GREEN}
SCAN_LABEL_KEYS = {
    "network": "scan_tag_network",
    "dynload": "scan_tag_dynload",
    "native": "scan_tag_native",
    "exec": "scan_tag_exec",
    "powershell": "scan_tag_powershell",
    "unreadable": "scan_tag_unreadable",
}
ZIP_READ_ERRORS = (zipfile.BadZipFile, zipfile.LargeZipFile, zlib.error, EOFError, NotImplementedError,
                   RuntimeError, OSError, KeyError)
JUNK_TEMP_EXT = (".tmp", ".part", ".crdownload", ".download")
LOG_RETENTION_KEEP = 20
RENAME_TAGS = ("_CLIENT", "_SERVER", "_BOTH", "_UNIDENTIFIED")
SEP_LINE = f"{DIM}{'-=' * 22}{RESET}"

# c161
T = {
    "ru": {
        "no_internet": "Интернет для скрипта отсутствует",
        "no_internet_detail": ' функции будут ограничены.',
        "err_toml_missing": "нет toml и fabric.mod.json",
        "err_toml_parse": "не удалось распарсить toml",
        "err_badzip": "битый zip",
        "err_small": "файл слишком маленький",
        "err_fabric_parse": "не удалось распарсить fabric.mod.json",
        "fabric_env_tag": "(fabric.mod.json) ",
        "search_label": "поиск",
        "direct_label": "прямая",
        "by_name": '(по имени)',
        "header_list": "=== Список модов: сторона ===",
        "header_client": "=== Клиентские моды ===",
        "no_client": "Клиентских модов не найдено.",
        "header_required": "=== Обязательные моды к добавлению ===",
        "no_required": "Ничего не пропущено.",
        "required_for": "требуется для",
        "header_optional": "=== Рекомендуемые (опциональные) моды ===",
        "no_optional": "Опциональных зависимостей не найдено.",
        "optional_for": "опционально для",
        "client_unknown_no_internet": "Нет сети, сторона (клиент/сервер) не определена, список может быть неполным.",
        "header_incompatible": "=== Несовместимости (заявлены авторами модов) ===",
        "no_incompatible": "Несовместимостей не найдено.",
        "incompatible_note": "конфликт заявлен в файле toml одного из модов",
        "header_duplicates": "=== Дубликаты модов ===",
        "no_duplicates": "Дубликатов не найдено.",
        "header_identical": "=== Идентичные jar-файлы (по содержимому) ===",
        "no_identical": "Идентичных файлов не найдено.",
        "header_disabled": "=== Отключённые / неопознанные файлы ===",
        "no_disabled": "Отключённых или неопознанных файлов не найдено.",
        "log_saved": "лог сохранён",
        "banner_title": "  Auto-Modpacker by A Simple Block",
        "banner_verify": 'Не хочешь верить на слово, проверь скрипт сам:',
        "banner_vt": 'VirusTotal (загрузи файл на скан):  https://www.virustotal.com/gui/home/upload',
        "banner_gemini": 'Gemini (спроси, что делает код):    https://gemini.google.com/app',
        "banner_guide": "Гайд по CurseForge API-ключу (не обязателен: без него сторона мода и обновления проверяются только через Modrinth; с ключом CurseForge подключается наравне с Modrinth, как резервный источник по стороне и обновлениям, плюс вторая прямая ссылка для Атернос):",
        "banner_guide1": '1. Зайти или зарегистрироваться на https://console.curseforge.com',
        "banner_guide2": '2. В личном кабинете: API Keys -> создать Core API Key',
        "banner_guide3": '3. Скопировать ключ, вставить командой: key <твой_ключ>',
        "banner_key_note": 'Ключ сохраняется локально в CurseForgeApiKey_DO_NOT_SHARE.txt. Не пересылай этот файл.',
        "commands": 'Команды: run | aternos | explain <modid> | stats | updates | scan | clean | report | search | show | save | saveall | bulk | addons | build | newaddons | importlink | modupdate | finder <команда> | help | exit',
        "cf_fallback_tag": "(CurseForge) ",
        "side_list_tag": "(список Manual-Side-Mods) ",
        "key_set": 'CurseForge API-ключ установлен и сохранён на устройстве он никуда не передаётся.',
        "logs_header": "=== Доступные снапшоты ===",
        "logs_none": "Пока нет ни одного сохранённого прогона.",
        "compare_need_two": "Недостаточно снапшотов для сравнения (нужно минимум 2).",
        "compare_bad_index": "Неверный индекс файла.",
        "compare_bad_args": "Использование: compare <N> | compare fileX fileY",
        "compare_header": "=== Сравнение: {old} -> {new} ===",
        "compare_added": "-- Добавлены --",
        "compare_deleted": "-- Удалены --",
        "compare_changed": "-- Изменился вердикт (сторона) --",
        "compare_updated": "-- Обновилась версия --",
        "compare_empty": '(пусто)',

        "run_first": "Сначала выполните run.",

        "sect_client": "Client",
        "sect_server": "Server",
        "sect_both": "Both",
        "sect_failed": "Не удалось определить",
        "sect_manual": "Вручную",
        "stats_jij": "Встроенных (Jar in Jar)",
        "manual_intro": 'Не удалось определить сторону у {n} мод(ов). Выберите для каждого:',
        "manual_legend": 'R повторить | C Client | S Server | B Both | H справка | Enter пропустить | Q закончить',
        "manual_prompt": "[{i}/{n}] {name} [{modid}] [{fname}]  (R/C/S/B/H): ",
        "manual_help": 'R: заново запросить Modrinth и CurseForge для всех нерешённых, помогает если произошла ошибка.\n  C (Client): мод нужен только игроку (графика, интерфейс, звук), на сервер не ставится.\n  S (Server): мод нужен только серверу (оптимизация тиков, серверные утилиты).\n  B (Both): нужен и игроку и серверу (контент, механики, библиотеки).\n  Enter: не уверен, мод останется в списке «Не удалось», спросим при следующем run.\n  Q: закончить разбор.\n  Выбор C, S, B запоминается в .auto_modpacker_manual_sides.json второй раз вводит не нужно будет.',
        "manual_saved": 'Назначено вручную: {n}. сторона установлена.',
        "manual_retry": "Повторяю запросы для нерешённых...",

        "header_stats": "=== Modpack statistics ===",
        "stats_total": "Всего jar",
        "stats_valid": "Валидных модов",
        "stats_broken": "Битых jar",
        "stats_missing_toml": "Без toml",
        "stats_client": "Client-only",
        "stats_server": "Server-only",
        "stats_both": "Both",
        "stats_unknown": "Не определено",
        "stats_required": "Обязательных пропущено",
        "stats_optional": "Опциональных пропущено",
        "stats_conflicts": "Конфликтов",
        "stats_duplicates": "Дублей modId",
        "stats_identical": "Идентичных файлов",
        "stats_disabled": "Отключено/неопознано",

        "aternos_header": "=== Ссылки для Атернос ===",
        "aternos_footer": "Клиентские моды пропущены ({n}), их не нужно искать на сервере.",

        "explain_usage": "Использование: explain <modid>",
        "explain_not_found": "Мод с таким modId не найден в последнем run.",
        "explain_id": "ID",
        "explain_version": "Версия",
        "explain_side": "Сторона",
        "explain_client": "  Client",
        "explain_server": "  Server",
        "explain_deps": "Зависимости",
        "explain_deps_none": '(нет)',
        "explain_optional_tag": '(опционально)',
        "explain_used_by": "Используется как зависимость у",
        "explain_used_by_none": '(никто не зависит)',
        "explain_sources": "Найден на",
        "explain_sources_none": 'не найден (или не проверялось)',
        "explain_update": "Обновление",
        "explain_integrity": "SHA256",
        "explain_file_section": "Файл",
        "explain_size": 'Размер',
        "explain_entries": 'Записей в архиве',
        "explain_meta": "  META-INF",
        "explain_assets": "  Assets",
        "explain_data": "  Data",
        "explain_classes": 'Классов',
        "explain_mixins": 'Mixin-конфигов',

        "side_disable_usage": "Использование: disable client|server|both",
        "side_unknown_no_run": 'Сторона неизвестна, сначала запустите run для проверки.',
        "disable_none": "Подходящих модов не найдено.",
        "disable_preview": "Будут отключены (переименованы в .jar.disabled):",
        "confirm_prompt": 'Подтвердить? (yes/no):',
        "cancelled": "Отменено.",
        "disable_done": "Отключено файлов: {n}",
        "enable_none": "Отключённых модов не найдено.",
        "enable_preview": "Будут включены обратно (.jar.disabled -> .jar):",
        "enable_done": "Включено обратно файлов: {n}",
        "rename_preview": "Будут переименованы (тег стороны в имени):",
        "rename_done": "Переименовано файлов: {n}",
        "unrename_none": "Файлов с тегом стороны не найдено.",
        "unrename_preview": "Будут возвращены к исходному имени:",
        "unrename_done": "Возвращено файлов: {n}",

        "crash_usage": "Использование: crash <полное.имя.Класса>",
        "crash_none": "Класс не найден ни в одном jar (включая отключённые).",
        "crash_found_in": "Найден в",

        "graphic_singles": "SINGLE MODS",

        "header_orphan": '=== Одиночные-моды (без связей с другими модами в сборке) ===',
        "orphan_none": "Изолированных модов не найдено.",
        "orphan_note": "Сюда попадают и самостоятельные контент-моды. Отсутствие связей не значит, что мод не нужен.",

        "header_scan": "=== Scan: уровень риска и взаимодействия с системой ===",
        "scan_disclaimer": 'Это инструмент который показывает уровень взаимодействия с системой(сеть, классы, файлы). Socket, Netty или .dll чтобы не пропустить потенциально вредоносный мод.',
        "scan_tag_network": "сетевая библиотека",
        "scan_tag_dynload": "динамическая загрузка классов",
        "scan_tag_native": "нативная библиотека",
        "scan_tag_exec": "встроенный исполняемый файл",
        "scan_tag_powershell": "PowerShell-скрипт",
        "scan_tag_unreadable": "не удалось прочитать файл",
        "scan_none": "Ничего не найдено.",

        "header_dupres": "=== Дублирующиеся ресурсы (assets) между модами ===",
        "dupres_scanning": 'Сканирование assets по всем jar, это может занять время...',
        "dupres_none": 'Одинаковых предметов ресурсов между разными модами не найдено.',

        "version_usage": "Использование: version <minecraft> <loader_version> (без аргументов, показать текущее)",
        "version_none_set": "Целевая версия не задана.",
        "version_current": "Текущая цель: Minecraft {mc}, {name} {loader}",
        "version_header": "===================",
        "version_mc_line": " Minecraft: {mc}",
        "version_loader_line": " {name}: {loader}",
        "version_detected": "Detected mods:",
        "version_unknown": 'нет ограничений версии Minecraft и загрузчика в метаданных мода',

        "updates_header": "=== Updates ===",
        "updates_uptodate": "up to date",
        "updates_available": "UPDATE AVAILABLE",
        "updates_major": "possible major update",
        "updates_ahead": "установлена версия новее, чем найдена на площадке",
        "updates_unknown": 'не проверено (мод не найден на Modrinth/CurseForge перепроверьте подключение сети)',
        "updates_installed": "installed",
        "updates_latest": "latest",

        "header_timeline": "=== Timeline ===",
        "timeline_none": 'Нет сохранённых снапшотов, сначала запустите run хотя бы два раза.',
        "timeline_mods_word": "модов",
        "timeline_added_word": "добавлен",
        "timeline_removed_word": "удалён",
        "timeline_updated_word": "версия {name}: {old} -> {new}",
        "timeline_side_changed": 'у {name} изменилась сторона установленная модом (client/server/both)',
        "timeline_saved": "таймлайн сохранён",

        "help_header": "=== Команды ===",

        "aternos_recommended": "рекомендуется",

        "crashlog_header": "=== Crashlog ===",
        "crashlog_found": "Последний крашлог: {name} ({when})",
        "crashlog_none_dir": "Папка с крашлогами не найдена. Искал здесь: {paths}",
        "crashlog_readerr": "Не удалось прочитать файл крашлога: {err}",
        "crashlog_description": "Описание",
        "crashlog_suspects_header": 'Похоже, замешаны следующие моды:',
        "crashlog_suspects_none": 'Не удалось установить ошибку. проверьте файл крашлога вручную.',
        "crashlog_hint": "Полный текст: {path}",

        "remove_usage": "Использование: remove <modid|имя>",
        "remove_not_found": 'Мод не найден. Сначала запустите run.',
        "remove_depended_by": "зависимых модов",
        "remove_dependencies": "зависимостей",
        "remove_side_label": "сторона",
        "remove_safe_yes": "Можно безопасно удалить: ДА",
        "remove_safe_no": "Можно безопасно удалить: НЕТ",
        "remove_will_break": "Это сломает:",
        "remove_optional_users": 'Опционально используют (моды которые имеют поддержку данного мода):',
        "remove_files_affected": "Затронутых файлов",
        "remove_done": "Удалено: {name}",
        "remove_error": "Не удалось удалить файл: {err}",
        "remove_rerun_hint": "Запустите run заново, чтобы обновить список модов.",

        "export_usage": "Использование: export client|server <папка>",
        "export_title_server": "SERVER PACK",
        "export_title_client": "CLIENT PACK",
        "export_unknown_tag": 'сторона неизвестна, укажите вручную',
        "export_excluded_broken": "Исключены (не удалось прочитать): {names}",
        "export_copied": "Скопировано модов: {n} -> {path}",

        "install_usage": "Использование: install missing",
        "install_header": "=== Установка недостающих модов ===",
        "install_none": "Отсутствующих обязательных зависимостей нет.",
        "install_not_found": "не найден ни на Modrinth, ни на CurseForge",
        "install_source": "Источник",
        "install_version": "Версия",
        "install_compat": "Совместимость",
        "install_manual_only": 'Автозагрузка недоступна установите вручную',
        "install_nothing_to_download": "Ни для одного мода не нашлось файла для автозагрузки.",
        "install_confirm_prompt": 'Скачать всё, что доступно? (yes/no):',
        "install_done": "Скачано модов: {n}. Рекомендуется запустить run заново.",

        "update_usage": "Использование: update <modid|имя> | update all",
        "update_nothing": "Обновлений текущих модов не найдено.",
        "update_plan_header": "=== План обновления ===",
        "update_confirm_prompt": 'Обновить {n} мод(ов)? Перед этим будет сделан бэкап. (yes/no):',
        "update_backup_made": "Бэкап сохранён: {path}",
        "update_done": "Обновлено модов: {n}",
        "update_rerun_hint": "Рекомендуется запустить run заново, чтобы проверить результат.",
        "updates_no_match": "версия под {mc}/{loader} не найдена (у мода есть обновления, но не под вашу версию)",

        "disable_moved": "Перемещено в: {path}",

        "report_building": "Собираем отчёт...",
        "report_done": "Отчёт сохранён: {path}",
        "report_generated_label": "Сформирован",
        "report_target_label": "Целевая версия",
        "report_mods_label": "Список модов",
        "report_broken_label": "Битые файлы",

        "clean_header": "=== Очистка мусора ===",
        "clean_scanning": "Ищем старые версии модов, отключённые файлы, дубликаты, временные файлы и старые логи...",
        "clean_none": "Мусора не найдено.",
        "clean_total": "Итого: {n} файлов, {size:.1f} МБ. Перед удалением всё будет упаковано в архив.",
        "clean_done": "Готово: {archive}. Удалено файлов: {n}.",
        "clean_archive_error": "Не удалось создать архив: {err}",
        "clean_cat_old_version": "Старые версии модов",
        "clean_cat_disabled_flat": "Отключённые файлы (.jar.disabled)",
        "clean_cat_jar_old": "Файлы .jar.old",
        "clean_cat_temp": "Временные файлы",
        "clean_cat_duplicate": "Полные дубликаты файлов",
        "clean_cat_old_log": "Старые логи скрипта",
    },
    "en": {
        "no_internet": "No internet access for the script",
        "no_internet_detail": ' functions will be limited.',
        "err_toml_missing": "no toml or fabric.mod.json",
        "err_toml_parse": "failed to parse toml",
        "err_badzip": "corrupted zip",
        "err_small": "file too small",
        "err_fabric_parse": "failed to parse fabric.mod.json",
        "fabric_env_tag": "(fabric.mod.json) ",
        "search_label": "search",
        "direct_label": "direct",
        "by_name": '(by name)',
        "header_list": "=== Mod list: side ===",
        "header_client": "=== Client-only mods ===",
        "no_client": "No client-only mods found.",
        "header_required": "=== Required mods to add ===",
        "no_required": "Nothing missing.",
        "required_for": "required by",
        "header_optional": "=== Recommended (optional) mods ===",
        "no_optional": "No optional dependencies found.",
        "optional_for": "optional for",
        "client_unknown_no_internet": "No network, client/server side could not be determined, list may be incomplete.",
        "header_incompatible": "=== Incompatibilities (declared by mod authors) ===",
        "no_incompatible": "No incompatibilities found.",
        "incompatible_note": "conflict declared in a mod's toml file",
        "header_duplicates": "=== Duplicate mods ===",
        "no_duplicates": "No duplicates found.",
        "header_identical": "=== Identical jar files (by content) ===",
        "no_identical": "No identical files found.",
        "header_disabled": "=== Disabled / unrecognized files ===",
        "no_disabled": "No disabled or unrecognized files found.",
        "log_saved": "log saved",
        "banner_title": "  Auto-Modpacker by A Simple Block",
        "banner_verify": "Don't take my word for it; check the script yourself:",
        "banner_vt": 'VirusTotal (upload the file to scan):  https://www.virustotal.com/gui/home/upload',
        "banner_gemini": 'Gemini (ask what the code does):    https://gemini.google.com/app',
        "banner_guide": "CurseForge API key guide (optional: without it, side detection and updates rely on Modrinth only; with a key, CurseForge is used on par with Modrinth, a fallback source for side detection and updates, plus a second direct link for Aternos):",
        "banner_guide1": '1. Sign in or register at https://console.curseforge.com',
        "banner_guide2": '2. In your account: API Keys -> create Core API Key',
        "banner_guide3": '3. Copy the key and enter it with: key <your_key>',
        "banner_key_note": 'The key is saved locally in CurseForgeApiKey_DO_NOT_SHARE.txt. Do not forward this file.',
        "commands": 'Commands: run | aternos | explain <modid> | stats | updates | scan | clean | report | search | show | save | saveall | bulk | addons | build | newaddons | importlink | modupdate | finder <command> | help | exit',
        "cf_fallback_tag": "(CurseForge) ",
        "side_list_tag": "(Manual-Side-Mods list) ",
        "key_set": 'The CurseForge API key has been set and saved on the device; it is not sent anywhere.',
        "logs_header": "=== Available snapshots ===",
        "logs_none": "No saved runs yet.",
        "compare_need_two": "Not enough snapshots to compare (need at least 2).",
        "compare_bad_index": "Invalid file index.",
        "compare_bad_args": "Usage: compare <N> | compare fileX fileY",
        "compare_header": "=== Compare: {old} -> {new} ===",
        "compare_added": "-- Added --",
        "compare_deleted": "-- Deleted --",
        "compare_changed": "-- Verdict changed (side) --",
        "compare_updated": "-- Version updated --",
        "compare_empty": '(empty)',

        "run_first": "Run `run` first.",

        "sect_client": "Client",
        "sect_server": "Server",
        "sect_both": "Both",
        "sect_failed": "Could not determine",
        "sect_manual": "Manual",
        "stats_jij": "Embedded (Jar in Jar)",
        "manual_intro": 'Could not determine the side for {n} mod(s). Choose for each one:',
        "manual_legend": 'R repeat | C Client | S Server | B Both | H help | Enter skip | Q finish',
        "manual_prompt": "[{i}/{n}] {name} [{modid}] [{fname}]  (R/C/S/B/H): ",
        "manual_help": 'R: query Modrinth and CurseForge again for all unresolved mods; this can help after an error.\n  C (Client): the mod is needed only by the player (graphics, interface, sound); do not install it on the server.\n  S (Server): the mod is needed only by the server (tick optimization, server utilities).\n  B (Both): the mod is needed by both the player and the server (content, mechanics, libraries).\n  Enter: if you are unsure, the mod stays under "Could not determine"; you will be asked again on the next run.\n  Q: finish the review.\n  Choices C, S, and B are saved in .auto_modpacker_manual_sides.json, so you will not need to enter them again.',
        "manual_saved": 'Manually assigned: {n}. The side has been set.',
        "manual_retry": "Retrying lookups for unresolved mods...",

        "header_stats": "=== Modpack statistics ===",
        "stats_total": "Total JAR",
        "stats_valid": "Valid mods",
        "stats_broken": "Broken JAR",
        "stats_missing_toml": "Missing TOML",
        "stats_client": "Client-only",
        "stats_server": "Server-only",
        "stats_both": "Both",
        "stats_unknown": "Undetermined",
        "stats_required": "Required missing",
        "stats_optional": "Optional missing",
        "stats_conflicts": "Conflicts",
        "stats_duplicates": "Duplicate modId",
        "stats_identical": "Identical files",
        "stats_disabled": "Disabled/unrecognized",

        "aternos_header": "=== Aternos links ===",
        "aternos_footer": "Client-only mods skipped ({n}), no need to search them for the server.",

        "explain_usage": "Usage: explain <modid>",
        "explain_not_found": "No mod with that modId in the last run.",
        "explain_id": "ID",
        "explain_version": "Version",
        "explain_side": "Side",
        "explain_client": "  Client",
        "explain_server": "  Server",
        "explain_deps": "Dependencies",
        "explain_deps_none": '(none)',
        "explain_optional_tag": '(optional)',
        "explain_used_by": "Used by",
        "explain_used_by_none": '(nobody depends on it)',
        "explain_sources": "Found on",
        "explain_sources_none": 'not found (or not checked)',
        "explain_update": "Update",
        "explain_integrity": "SHA256",
        "explain_file_section": "File",
        "explain_size": 'Size',
        "explain_entries": 'Entries in archive',
        "explain_meta": "  META-INF",
        "explain_assets": "  Assets",
        "explain_data": "  Data",
        "explain_classes": 'Classes',
        "explain_mixins": 'Mixin configs',

        "side_disable_usage": "Usage: disable client|server|both",
        "side_unknown_no_run": 'The side is unknown; run `run` first to check.',
        "disable_none": "No matching mods found.",
        "disable_preview": "Will be disabled (renamed to .jar.disabled):",
        "confirm_prompt": 'Confirm? (yes/no):',
        "cancelled": "Cancelled.",
        "disable_done": "Disabled files: {n}",
        "enable_none": "No disabled mods found.",
        "enable_preview": "Will be re-enabled (.jar.disabled -> .jar):",
        "enable_done": "Re-enabled files: {n}",
        "rename_preview": "Will be renamed (side tag added to filename):",
        "rename_done": "Renamed files: {n}",
        "unrename_none": "No files with a side tag found.",
        "unrename_preview": "Will be restored to the original name:",
        "unrename_done": "Restored files: {n}",

        "crash_usage": "Usage: crash <full.class.Name>",
        "crash_none": "Class not found in any jar (including disabled).",
        "crash_found_in": "Found in",

        "graphic_singles": "SINGLE MODS",

        "header_orphan": '=== Standalone mods (no links to other mods in the pack) ===',
        "orphan_none": "No isolated mods found.",
        "orphan_note": "This also includes standalone content mods. No ties doesn't mean the mod is unneeded.",

        "header_scan": "=== Scan: risk / system-interaction level ===",
        "scan_disclaimer": 'This tool shows how a mod interacts with the system (network, classes, files). It checks for Socket, Netty, or .dll files to help detect potentially malicious mods.',
        "scan_tag_network": "network library",
        "scan_tag_dynload": "dynamic class loading",
        "scan_tag_native": "native library",
        "scan_tag_exec": "embedded executable",
        "scan_tag_powershell": "PowerShell script",
        "scan_tag_unreadable": "could not read the file",
        "scan_none": "Nothing found.",

        "header_dupres": "=== Duplicate assets across mods ===",
        "dupres_scanning": 'Scanning assets in all JAR files; this may take a while...',
        "dupres_none": 'No identical resource items were found across different mods.',

        "version_usage": "Usage: version <minecraft> <loader_version> (no args, show current)",
        "version_none_set": "No target version set.",
        "version_current": "Current target: Minecraft {mc}, {name} {loader}",
        "version_header": "===================",
        "version_mc_line": " Minecraft: {mc}",
        "version_loader_line": " {name}: {loader}",
        "version_detected": "Detected mods:",
        "version_unknown": 'no Minecraft or loader version limits are declared in the mod metadata',

        "updates_header": "=== Updates ===",
        "updates_uptodate": "up to date",
        "updates_available": "UPDATE AVAILABLE",
        "updates_major": "possible major update",
        "updates_ahead": "the installed version is newer than the one found on the platform",
        "updates_unknown": 'not checked (the mod was not found on Modrinth/CurseForge; check your network connection again)',
        "updates_installed": "installed",
        "updates_latest": "latest",

        "header_timeline": "=== Timeline ===",
        "timeline_none": 'No saved snapshots. Run `run` at least twice first.',
        "timeline_mods_word": "mods",
        "timeline_added_word": "added",
        "timeline_removed_word": "removed",
        "timeline_updated_word": "{name} version: {old} -> {new}",
        "timeline_side_changed": 'The side assigned to {name} has changed (client/server/both)',
        "timeline_saved": "timeline saved",

        "help_header": "=== Commands ===",

        "aternos_recommended": "recommended",

        "crashlog_header": "=== Crashlog ===",
        "crashlog_found": "Latest crash report: {name} ({when})",
        "crashlog_none_dir": "Crash-reports folder not found. Looked in: {paths}",
        "crashlog_readerr": "Couldn't read the crash report file: {err}",
        "crashlog_description": "Description",
        "crashlog_suspects_header": 'These mods appear to be involved:',
        "crashlog_suspects_none": 'Could not identify the error. Check the crash log manually.',
        "crashlog_hint": "Full text: {path}",

        "remove_usage": "Usage: remove <modid|name>",
        "remove_not_found": 'Mod not found. Run `run` first.',
        "remove_depended_by": "depended on by",
        "remove_dependencies": "dependencies",
        "remove_side_label": "side",
        "remove_safe_yes": "Safe to remove: YES",
        "remove_safe_no": "Safe to remove: NO",
        "remove_will_break": "This will also break:",
        "remove_optional_users": 'Mods that optionally use this mod (they will lose the integration if it is removed):',
        "remove_files_affected": "Files affected",
        "remove_done": "Removed: {name}",
        "remove_error": "Couldn't delete the file: {err}",
        "remove_rerun_hint": "Run `run` again to refresh the mod list.",

        "export_usage": "Usage: export client|server <folder>",
        "export_title_server": "SERVER PACK",
        "export_title_client": "CLIENT PACK",
        "export_unknown_tag": 'side unknown; specify it manually',
        "export_excluded_broken": "Excluded (couldn't be read): {names}",
        "export_copied": "Copied mods: {n} -> {path}",

        "install_usage": "Usage: install missing",
        "install_header": "=== Installing missing mods ===",
        "install_none": "No missing required dependencies.",
        "install_not_found": "not found on Modrinth or CurseForge",
        "install_source": "Source",
        "install_version": "Version",
        "install_compat": "Compatibility",
        "install_manual_only": 'Automatic download is unavailable; install the mod manually.',
        "install_nothing_to_download": "No mod had a file available for auto-download.",
        "install_confirm_prompt": 'Download everything available? (yes/no):',
        "install_done": "Downloaded mods: {n}. Running `run` again is recommended.",

        "update_usage": "Usage: update <modid|name> | update all",
        "update_nothing": "No updates were found for the installed mods.",
        "update_plan_header": "=== Update plan ===",
        "update_confirm_prompt": 'Update {n} mod(s)? A backup will be made first. (yes/no):',
        "update_backup_made": "Backup saved: {path}",
        "update_done": "Updated mods: {n}",
        "update_rerun_hint": "Running `run` again is recommended to verify the result.",
        "updates_no_match": "no version found for {mc}/{loader} (the mod has updates, but not for your target version)",

        "disable_moved": "Moved to: {path}",

        "report_building": "Preparing the report...",
        "report_done": "Report saved: {path}",
        "report_generated_label": "Generated",
        "report_target_label": "Target version",
        "report_mods_label": "Mod list",
        "report_broken_label": "Broken files",

        "clean_header": "=== Cleanup ===",
        "clean_scanning": "Looking for old mod versions, disabled files, duplicates, temporary files, and old logs...",
        "clean_none": "No junk found.",
        "clean_total": "Total: {n} files, {size:.1f} MB. Everything will be archived before removal.",
        "clean_done": "Done: {archive}. Files removed: {n}.",
        "clean_archive_error": "Couldn't create the archive: {err}",
        "clean_cat_old_version": "Old mod versions",
        "clean_cat_disabled_flat": "Disabled files (.jar.disabled)",
        "clean_cat_jar_old": ".jar.old files",
        "clean_cat_temp": "Temporary files",
        "clean_cat_duplicate": "Exact duplicate files",
        "clean_cat_old_log": "Old script logs",
    },
}

T["ru"].update({
    "sect_broken": "Битые файлы",
    "manual_tag": 'вручную',
    "manual_neterr": '(ошибка сети, попробуйте заново R)',
    "manual_retry_result": 'Повтор: определено {ok} из {n}.',
    "manual_saved": 'Назначено вручную: {n}.',
    "need_target": 'Сначала задайте целевую версию: version <minecraft> <версия загрузчика>. Без неё можно скачать сборку под другую версию игры.',
    "install_page": 'Страница',
    "install_exists": 'файл уже есть, пропущено',
    "run_interrupted": 'Прервано. Результат этого run не сохранён.',
    "cf_denied": 'CurseForge отклонил API-ключ (401/403), CurseForge пропущен. Установите ключ заново: key <ключ>',
    "net_errors": 'Сетевых ошибок при запросах: {n}. У части модов сторона могла не определиться, в списке неопределённых нажми R.',
    "version_usage": 'Использование: version <minecraft> <версия_loader> [neoforge|forge|fabric] (без аргументов, показать текущее)',
})
T["en"].update({
    "sect_broken": "Broken files",
    "manual_tag": "manual",
    "manual_neterr": "(network error; press R to retry)",
    "manual_retry_result": "Retry: resolved {ok} of {n}.",
    "manual_saved": "Assigned manually: {n}. The side has been saved.",
    "need_target": "Set the target version first: version <minecraft> <loader version>. Without it, a build for another game version could be downloaded.",
    "install_page": "Page",
    "install_exists": "file already exists, skipped",
    "run_interrupted": "Interrupted. The result of this run was not saved.",
    "cf_denied": "CurseForge rejected the API key (401/403), so the platform will be skipped. Set the key again: key <key>.",
    "net_errors": "Network errors during lookups: {n}. Some mods may have no side assigned. Press R in the unresolved list to retry.",
    "version_usage": "Usage: version <minecraft> <loader_version> [neoforge|forge|fabric] (no args, show current)",
})

HELP_GROUPS = {
    "ru": [
        ('Настройка', [
            ("key <ключ>",
             'Сохраняет CurseForge ключ в CurseForgeApiKey_DO_NOT_SHARE.txt рядом со скриптом.\nпожалуйста не делитесь не отправляйте этот файл никому.\nБез ключа сторона и обновления идут только через Modrinth.\nКлюч хранится только на вашем устройстве никуда не отправляется'),
        ]),
        ('Скан и данные о модах', [
            ("run",
             'Главная команда.\nРазбирает мод проводит проверку через Modrinth и CurseForge а после определяет сторону сначала по списку Manual-Side-Mods с GitHub, потом через Modrinth, а если там нет то через CurseForge все вопросы к установленной стороне мода к Modrinth и CurseForge если нашли ошибку пишите в Issues на гитхабе.\nПечатает моды по секциям Client, Server, Both и Не удалось определить, потом недостающие зависимости, конфликты, дубли modId, одинаковые файлы и статистику.\nЕсли одна площадка не находит проект, подключается сопоставление ищем вторую площадку по slug, названию и SHA-1, дополняет идентификаторы для updates и уточняет сторону по доступным метаданным.\nДля неопределённых даёт выбрать вручную: C, S, B, R повторить запрос, H справка.\nЛог и снапшот падают в script_logs/.\nОстальные команды работают по последнему run.'),
            ("stats",
             'Сводка по последнему run.\nСколько jar, валидных, битых и без toml, разбивка по сторонам.\nСколько зависимостей не хватает, конфликты, дубли, отключённые и встроенные моды.'),
            ('explain <modid|имя>',
             'Карточка мода: версия, сторона, зависимости (есть или нет), кто от него зависит.\nГде найден (Modrinth, CurseForge) и статус обновления.\nSHA256 и данные по jar: размер, записи, assets, data, классы, mixin.'),
            ("version <mc> <loader>",
             'Задаёт цель: Minecraft и загрузчик (по умолчанию NeoForge, forge или fabric третьим аргументом).\nСверяет её с диапазонами в toml или fabric.mod.json каждого мода.\nЦель дальше влияет на updates, update и install missing, версии под другую сборку игнорируются.\nБез аргументов показывает текущую цель.'),
            ("updates",
             'Проверяет обновления у всех модов: сначала Modrinth, потом CurseForge.\nПоказывает установленную и последнюю версию с источником.'
             ),
            ("report",
             'Собирает modpack_report.html рядом со скриптом.\nВнутри статистика, таблица модов, зависимости, конфликты, обновления для удобного просмотра вне скрипта или отправить другому человеку.'),
        ]),
        ('Зависимости и структура', [
            ("graphic",
             'Дерево зависимостей: под каждой базой аддоны, которые от неё зависят.\nМоды без связей идут отдельным блоком SINGLE MODS.'),
            ("orphan",
             'Моды, которые ни от кого не зависят, и от них никто не зависит.\nЭто не значит что мод лишний, самостоятельные контентные моды тоже тут если хотите удалить используйте комманду remove подробнее в help о remove.'),
            ('crash <класс>',
             'Ищет полное имя класса во всех jar, включая отключённые и папку disabled/.\nПригодится когда в логах только класс без названия мода а крашлога нет.'),
            ("crashlog",
             'Берёт последний крашлог из crash-reports (папка выше mods, запасной вариант рядом со скриптом).\nВытаскивает описание и сопоставляет классы из стека с установленными jar.\nВидно какие моды замешаны.'),
        ]),
        ('Безопасность', [
            ("scan",
             'Ищет в .class следы сети (Netty, Socket, java.net.http, WebSocket, OkHttp) и динамической подгрузки классов.\nСмотрит подозрительные файлы внутри jar (.dll .so .exe .bat .cmd .ps1).\nУровни LOW, MEDIUM, HIGH показывают только насколько много доступа и что мод делает.\nЭто полезный детектор если источник сомнительный.'),
            ("dupres",
             'Сравнивает SHA256 файлов из assets/ у разных модов и показывает одинаковые.\nПомогает найти пересечения ресурсов и оверрайды.\nНа большой сборке идёт долго.'),
        ]),
        ('Файлы модов', [
            ("disable client|server|both",
             'После подтверждения переименовывает моды выбранной стороны в .jar.disabled и кладёт в disabled/сторона/дата.\nНужен run с интернетом, иначе функционал ограничен.'),
            ("enable",
             'После подтверждения возвращает все .jar.disabled в корень как .jar.\nИмена, которые уже есть в корне, не перезаписывает.'),
            ("rename",
             'Добавляет к имени файла тег стороны из последнего run: _CLIENT, _SERVER, _BOTH или _UNIDENTIFIED.'),
            ("unrename",
             'Убирает эти теги, имена возвращаются.'),
            ('remove <modid|имя>',
             'Показывает что сломается без этого мода (required) и что просто потеряет опциональную интеграцию.\nПотом после подтверждения удаляет файл.\nДальше запустите run заново.'),
            ('export client|server <папка>',
             'Копирует в папку моды нужной стороны, плюс Both и моды с неопределённой стороной (они помечены для ручной проверки).\nОригиналы остаются на месте.'),
            ("install missing",
             'Ищет недостающие обязательные зависимости на Modrinth и CurseForge, подбирает файл под цель из version и после подтверждения качает.\nЕсли площадка не даёт прямую ссылку, покажет страницу для ручной загрузки.'),
            ("update",
             'Открывает центр обновления сборки: перенос модов на другую версию Minecraft (например 1.20.1 -> 1.21.1). Подкоманды: target, plan, list, show, pick, keep, drop, reset, channel, near, stage, apply, export, rollback, status, report, clear. Папка модов не меняется, пока не сделан apply (с бэкапом и откатом) или export в новую папку. update help - подробно.'),
            ("update plan 1.21.1 neoforge",
             'Анализирует все моды под новую версию: опознаёт их по хешу файла на Modrinth, ищет версию под цель, добавляет новые обязательные зависимости и объясняет, почему версии нет.'),
            ('update stage | apply | export <папка> | rollback',
             'Скачивает выбранное в update_stage с проверкой хеша и modId, применяет с бэкапом старых файлов в update_backup (откат: rollback) или собирает новую папку модов, не трогая старую.'),
            ('update all | update <modid|имя>',
             'Старый режим: обновить моды внутри текущей цели из version. Старые файлы копируются в backup/дата/mods. После обновления сборки лучше запустить run.'),
            ("clean",
             'Ищет мусор: старые версии одного мода (нужен run), .jar.disabled и .jar.old в корне, временные файлы, точные дубли и старые логи скрипта.\nВсё пакуется в clean_дата.zip и только потом удаляется.'),
        ]),
        ('Сервер (Атернос)', [
            ("aternos",
             'Ссылки для Атернос по последнему run: прямая на Modrinth, прямая на CurseForge (нужен ключ) и обычный поиск.\nРекомендуемая помечена.\nКлиентские моды в список не попадают.'),
        ]),
        ('История прогонов', [
            ("logs",
             'Список снапшотов из script_logs/ с номерами.\nНомера нужны для compare.'),
            ("timeline",
             'История сборки по всем снапшотам: что добавилось, что удалено, у кого сменилась версия или сторона.\nКопия лежит в timeline/.'),
            ("compare <N> | fileX fileY",
             'Сравнивает два снапшота.\ncompare N берёт N-й снапшот с конца и сравнивает с последним (compare 2 это предыдущий против последнего).\ncompare file1 file4 берёт снапшоты по номерам из logs.\nПоказывает добавленные, удалённые, сменившие сторону и обновлённые моды.'),
            ('buildcompare <папка1> <папка2>',
             'Сравнивает папки двух сборок, включая вложенную папку mods/.\nСопоставляет моды по modId, а при его отсутствии по названию. Показывает добавленные, удалённые, обновлённые и изменившиеся JAR.'),
        ]),
        ('Прочее', [
            ("help",
             'Этот список.'),
            ("exit",
             'Выход.'),
        ]),
    ],
    "en": [
        ("Setup", [
            ("key <key>",
             "Saves the CurseForge API key locally in CurseForgeApiKey_DO_NOT_SHARE.txt next to the script. "
             "Do not share this file. Without an API key, side detection and updates use Modrinth only. "
             "With a key, CurseForge is also used as a source for side detection and updates, provides "
             "a second direct Aternos link, and acts as a fallback for install missing. The key is sent "
             "to CurseForge when API requests are made."),
        ]),
        ("Scan and mod data", [
            ("run",
             "The main command. Reads every .jar file in the folder, including nested Jar-in-Jar entries, "
             "parses mods.toml or fabric.mod.json, and detects each mod's side through Modrinth first, "
             "then CurseForge when Modrinth has no usable data. It lists Client, Server, Both and "
             "Could not determine sections, followed by missing dependencies, conflicts, duplicate modIds, "
             "identical files and statistics. If one platform cannot find a project, Auto-Finder looks "
             "for a match on the other platform by slug, title and SHA-1, fills in platform IDs for updates, "
             "and refines the side using available metadata. For mods with an unknown side, you can choose "
             "manually: C, S or B; press R to retry the lookups or H for help. Logs and snapshots are saved "
             "to script_logs/. Other commands use the result of the latest run."),
            ("stats",
             "Summary of the last run: jar count, valid, broken and missing toml, side breakdown, "
             "missing dependencies, conflicts, duplicates, disabled and embedded mods."),
            ("explain <modid|name>",
             "Card for one mod: version, side, dependencies marked present or missing, who depends on "
             "it, where it was found (Modrinth, CurseForge), update status, SHA256 and jar details "
             "(size, entries, assets, data, classes, mixins)."),
            ("version <mc> <loader>",
             "Sets the target Minecraft version and loader (NeoForge by default; forge or fabric can be "
             "specified as the third argument). It checks the target against the ranges in each mod's "
             "toml or fabric.mod.json. The target then affects updates, update and install missing: "
             "versions for a different Minecraft/loader setup are ignored. With no arguments, this command shows the current target."),
            ("updates",
             "Checks for updates for every mod, querying Modrinth first and then CurseForge. Shows the "
             "installed and latest versions, along with the source."),
            ("report",
             "Builds modpack_report.html next to the script. It contains statistics, a mod table, dependencies, "
             "conflicts and updates. You can open the report in a browser or send it to someone else."),
        ]),
        ("Dependencies and structure", [
            ("graphic",
             "Dependency tree: under each base mod a list of addons that depend on it. Mods with no "
             "ties go to a separate SINGLE MODS block."),
            ("orphan",
             "Mods that do not depend on other mods in the pack and that no other mods depend on. "
             "This does not mean a mod is unnecessary: standalone content mods appear here too. "
             "To remove a mod, use the remove command; see its help entry for details."),
            ("crash <class>",
             "Searches every jar for a fully qualified class name, including disabled jars and the "
             "disabled/ folder. Useful when the logs show a class name but not the mod name and "
             "there is no crash report."),
            ("crashlog",
             "Takes the latest crash report from crash-reports (one folder above mods, fallback next "
             "to the script), pulls the description and matches stack classes to installed jars. "
             "Shows which mods are involved."),
        ]),
        ("Security", [
            ("scan",
             "Looks in .class files for network code (Netty, Socket, java.net.http, WebSocket, OkHttp), "
             "dynamic class loading and suspicious files inside jars (.dll .so .exe .bat .cmd .ps1). "
             "LOW, MEDIUM, and HIGH show which kinds of system interaction were detected.\n"
             "This is not an antivirus or proof of malicious behavior; use the result as a reason for further review, especially when the source is questionable."),
            ("dupres",
             "Compares SHA256 of files under assets/ across mods and lists identical ones. Helps spot "
             "overlapping resources and overrides. Slow on big packs."),
        ]),
        ("Mod files", [
            ("disable client|server|both",
             "After confirmation, renames mods of the chosen side to .jar.disabled and moves them to "
             "disabled/side/date. A run with internet access is required; without it, functionality is limited."),
            ("enable",
             "Moves every .jar.disabled back to the root as .jar after confirmation. Names that "
             "already exist in the root are not overwritten."),
            ("rename",
             "Adds the side tag from the last run to each filename: _CLIENT, _SERVER, _BOTH or "
             "_UNIDENTIFIED."),
            ("unrename",
             "Strips those tags and restores the original names."),
            ("remove <modid|name>",
             "Shows what breaks without this mod (required dependencies) and what only loses an "
             "optional integration, then deletes the file after confirmation. Run the scan again afterwards."),
            ("export client|server <folder>",
             "Copies mods of the chosen side plus Both and mods with an unknown side (marked for "
             "manual review) into a folder. Originals stay in place."),
            ("install missing",
             "Looks up missing required dependencies on Modrinth and CurseForge, picks a file for the "
             "target from version and downloads after confirmation. If a platform gives no direct "
             "link it shows the page for a manual download."),
            ("update",
             "Opens the modpack update center: move the mods to another Minecraft version (for example 1.20.1 -> 1.21.1). "
             "Subcommands: target, plan, list, show, pick, keep, drop, reset, channel, near, stage, apply, export, rollback, "
             "status, report, clear. The mods folder stays as is until apply (with a backup and undo) or export to a "
             "new folder. update help - details."),
            ("update plan 1.21.1 neoforge",
             "Analyses all mods for the new version: identifies them by file hash on Modrinth, looks for a version for "
             "the target, adds new required dependencies and explains why a version is missing."),
            ("update stage | apply | export <folder> | rollback",
             "Downloads the chosen files to update_stage with hash and modId checks, applies with a backup of the old "
             "files in update_backup (undo: rollback) or builds a new mods folder without touching the old one."),
            ("update all | update <modid|name>",
             "Legacy mode: update mods within the current target set by version. Old files are copied to "
             "backup/date/mods. After updating the pack, run the scan again."),
            ("clean",
             "Finds junk: old versions of one mod (needs a run), .jar.disabled and .jar.old in the "
             "root, temp files, exact duplicates and old script logs. Everything is zipped into "
             "clean_date.zip before it is removed."),
        ]),
        ("Server (Aternos)", [
            ("aternos",
             "Aternos links from the last run: direct Modrinth, direct CurseForge (needs a key) and a "
             "plain search. The recommended one is marked. Client-only mods are left out."),
        ]),
        ("Run history", [
            ("logs",
             "Numbered list of snapshots in script_logs/. The numbers are used by compare."),
            ("timeline",
             "Pack history across all snapshots: added, removed, version or side changes. A copy is "
             "saved to timeline/."),
            ("compare <N> | fileX fileY",
             "Compares two snapshots. compare N takes the Nth snapshot from the end and compares it "
             "to the latest (compare 2 is previous vs latest). compare file1 file4 uses numbers from "
             "logs. Shows added, removed, side-changed and updated mods."),
            ("buildcompare <folder1> <folder2>",
             "Compares two build folders, including nested mods/ directories.\n"
             "Matches mods by modId, or by name when modId is unavailable. Reports added, removed, updated and changed JAR files."),
        ]),
        ("Other", [
            ("help", "This list."),
            ("exit", "Quit."),
        ]),
    ],
}

LANG = "ru"

CACHE = {}
for _path in (CACHE_PATH,
              os.path.join(SCRIPT_DIR, ".mod_audit_cache.json")):  # старое имя кэша до переименования
    try:
        with open(_path, "r", encoding="utf-8") as f:
            _loaded = json.load(f)
    except (OSError, ValueError):
        continue
    if isinstance(_loaded, dict):
        for _key, _entry in _loaded.items():
            CACHE.setdefault(_key, _entry)
    if _path != CACHE_PATH:
        try:
            os.remove(_path)  # перенесён в общий кэш
        except OSError:
            pass
# c010
CACHE = {k: v for k, v in CACHE.items()
         if isinstance(v, dict) and "ts" in v and (v.get("v") is not None or v.get("fmt") == 2)}

# разовый перенос служебных файлов со старым именем mod_audit_* на новое имя
for _old_name, _new_name in (
    (".mod_audit_manual_sides.json", ".auto_modpacker_manual_sides.json"),
    (".mod_audit_update.json", ".auto_modpacker_update.json"),
    (".mod_audit_modules.json", ".auto_modpacker_modules.json"),
):
    _old_path = os.path.join(SCRIPT_DIR, _old_name)
    _new_path = os.path.join(SCRIPT_DIR, _new_name)
    if not os.path.exists(_old_path):
        continue
    if os.path.exists(_new_path):
        try:
            os.remove(_old_path)  # новый файл уже есть, старый больше не нужен
        except OSError:
            pass
    else:
        try:
            os.replace(_old_path, _new_path)
        except OSError:
            pass

def save_cache():
    tmp = CACHE_PATH + ".tmp"
    try:
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(CACHE, f, ensure_ascii=False)
        os.replace(tmp, CACHE_PATH)  # c011
    except OSError:
        pass

REPORT_LINES = []
CONSOLE_FILE = None

def say(line=""):
    print(line)
    if CONSOLE_FILE:
        try:
            CONSOLE_FILE.write(strip_ansi(line) + "\n")
            CONSOLE_FILE.flush()
        except OSError:
            pass

def out(line=""):
    say(line)
    REPORT_LINES.append(strip_ansi(line))

def log_console_raw(line):
    if CONSOLE_FILE:
        try:
            CONSOLE_FILE.write(line + "\n")
            CONSOLE_FILE.flush()
        except OSError:
            pass

def redact_for_log(raw_line):
    parts = raw_line.split(maxsplit=1)
    if parts and parts[0] == "key":
        return "key <redacted>"
    return raw_line

# c012
def cache_get(key):
    entry = CACHE.get(key)
    if entry is None:
        return "MISS"
    if not isinstance(entry, dict) or "ts" not in entry:
        return "MISS"
    if time.time() - entry["ts"] > CACHE_TTL_SECONDS:
        return "MISS"
    return entry.get("v")

def cache_set(key, value):
    CACHE[key] = {"v": value, "ts": time.time(), "fmt": 2}

# c013
MR_API = "https://api.modrinth.com/v2"
CF_API = "https://api.curseforge.com/v1"
NET_STATS = {"errors": 0, "cf_denied": False}
HTTP_RETRIES = 2
# c014
STRICT_NAME_MATCH = True

SIDE_LIST_URL = "https://raw.githubusercontent.com/SimpleBlockDev/Auto-Modpacker/main/Manual-Side-Mods/list.txt"
SIDE_LIST_CACHE_TTL = 24 * 3600
SIDE_LIST_CACHE_KEY = "side_list_v1"
_SIDE_LIST_STATE = None

def fetch_side_list_text():
    try:
        req = urllib.request.Request(SIDE_LIST_URL, headers={"User-Agent": "auto-modpacker"})
        with urllib.request.urlopen(req, timeout=10) as resp:
            return "ok", resp.read().decode("utf-8", "replace")
    except (urllib.error.HTTPError, urllib.error.URLError, OSError, ValueError):
        return "error", None

def parse_side_list(text):
    sides = {}
    for line in (text or "").splitlines():
        raw = line.strip()
        if not raw or raw.startswith("#"):
            continue
        mod_id, _, side = raw.partition("=")
        side = side.split("#", 1)[0].strip().lower()
        mod_id = mod_id.strip().lower()
        if mod_id and side in ("client", "server", "both"):
            sides[mod_id] = side
    return sides

def load_side_list(allow_fetch):
    global _SIDE_LIST_STATE
    if isinstance(_SIDE_LIST_STATE, dict):
        return _SIDE_LIST_STATE
    cached = CACHE.get(SIDE_LIST_CACHE_KEY)
    entry = cached if isinstance(cached, dict) else None
    cached_v = entry.get("v") if isinstance(entry, dict) else None
    fresh = isinstance(cached_v, dict) and time.time() - entry.get("ts", 0) <= SIDE_LIST_CACHE_TTL
    if not fresh and allow_fetch:
        status, text = fetch_side_list_text()
        if status == "ok":
            parsed = parse_side_list(text)
            cache_set(SIDE_LIST_CACHE_KEY, parsed)
            _SIDE_LIST_STATE = parsed
            return parsed
    if isinstance(cached_v, dict):
        _SIDE_LIST_STATE = cached_v
        return cached_v
    _SIDE_LIST_STATE = {}
    return _SIDE_LIST_STATE

def list_side_for(modid, allow_fetch):
    if not modid:
        return None
    return load_side_list(bool(allow_fetch)).get(str(modid).strip().lower())

def check_internet():
    try:
        req = urllib.request.Request(MR_API, headers={"User-Agent": "auto-modpacker"})
        with urllib.request.urlopen(req, timeout=5):
            pass
        return True
    except urllib.error.HTTPError:
        return True
    except Exception:
        return False


def http_get_json(url, headers=None, timeout=10):
    # c015
    hdrs = {"User-Agent": "auto-modpacker"}
    if headers:
        hdrs.update(headers)
    for attempt in range(HTTP_RETRIES + 1):
        try:
            req = urllib.request.Request(url, headers=hdrs)
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return "ok", json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return "notfound", None
            if e.code in (401, 403) and "curseforge" in url:
                NET_STATS["cf_denied"] = True
                break
            if (e.code == 429 or e.code >= 500) and attempt < HTTP_RETRIES:
                try:
                    wait = int(e.headers.get("Retry-After", "2"))
                except (AttributeError, TypeError, ValueError):
                    wait = 2
                time.sleep(min(max(wait, 1), 10))
                continue
            break
        except (OSError, ValueError, http.client.HTTPException):
            if attempt < HTTP_RETRIES:
                time.sleep(1 + attempt)
                continue
            break
    NET_STATS["errors"] += 1
    return "error", None


def cached_get_json(cache_key, url, headers=None, slim=None):
    # c016
    cached = cache_get(cache_key)
    if cached != "MISS":
        return cached
    status, data = http_get_json(url, headers)
    if status == "ok":
        try:
            value = slim(data) if slim else data
        except (AttributeError, TypeError):
            NET_STATS["errors"] += 1
            return None
        cache_set(cache_key, value)
        return value
    if status == "notfound":
        cache_set(cache_key, None)
    return None


def _slim_project(p):
    if not isinstance(p, dict):
        return p
    keys = ("id", "project_id", "slug", "title", "client_side", "server_side", "downloads", "project_type")
    return {k: p.get(k) for k in keys if k in p}


def _slim_search(d):
    return [_slim_project(h) for h in (d.get("hits") or []) if isinstance(h, dict)]


def _slim_versions(d):
    result = []
    for v in d if isinstance(d, list) else []:
        if not isinstance(v, dict):
            continue
        files = [{"url": f.get("url"), "filename": f.get("filename"), "primary": f.get("primary")}
                 for f in (v.get("files") or []) if isinstance(f, dict)]
        result.append({
            "version_number": v.get("version_number"),
            "date_published": v.get("date_published"),
            "game_versions": v.get("game_versions"),
            "loaders": v.get("loaders"),
            "version_type": v.get("version_type"),
            "files": files,
        })
    return result


def _slim_cf_mod(x):
    links = x.get("links") if isinstance(x.get("links"), dict) else {}
    return {"id": x.get("id"), "slug": x.get("slug"), "name": x.get("name"),
            "links": {"websiteUrl": links.get("websiteUrl")}}


def _slim_cf_list(d):
    return [_slim_cf_mod(x) for x in (d.get("data") or []) if isinstance(x, dict)]


def _slim_cf_files(d):
    result = []
    for f in d.get("data") or []:
        if not isinstance(f, dict):
            continue
        result.append({
            "fileDate": f.get("fileDate"),
            "displayName": f.get("displayName"),
            "fileName": f.get("fileName"),
            "gameVersions": f.get("gameVersions"),
            "downloadUrl": f.get("downloadUrl"),
            "releaseType": f.get("releaseType"),
        })
    return result


def _norm(s):
    return re.sub(r"[^a-z0-9]", "", str(s or "").lower())


def pick_search_hit(hits, display_name, modid, title_key):
    # c018
    hits = [h for h in (hits or []) if isinstance(h, dict)]
    nd, nm = _norm(display_name), _norm(modid)
    for h in hits:
        title, slug = _norm(h.get(title_key)), _norm(h.get("slug"))
        if (nd and (title == nd or slug == nd)) or (nm and (slug == nm or title == nm)):
            return h
    if STRICT_NAME_MATCH:
        return None
    return hits[0] if hits else None


def _cf_headers(api_key):
    return {"x-api-key": api_key, "Accept": "application/json"}


def _cf_ready(api_key):
    return bool(api_key) and not NET_STATS.get("cf_denied")


def fetch_modrinth(modid):
    if not modid:
        return None
    url = f"{MR_API}/project/{urllib.parse.quote(str(modid), safe='')}"
    result = cached_get_json(f"proj:{modid}", url, slim=_slim_project)
    if isinstance(result, dict) and result.get("project_type") not in (None, "mod"):
        return None
    return result


def search_modrinth(display_name, modid=None):
    if not display_name:
        return None
    facets = urllib.parse.quote('[["project_type:mod"]]', safe="")
    url = f"{MR_API}/search?query={urllib.parse.quote(str(display_name))}&facets={facets}&limit=5"
    hits = cached_get_json(f"search2:{str(display_name).lower()}", url, slim=_slim_search)
    return pick_search_hit(hits, display_name, modid, "title")


def fetch_modrinth_versions(project_id):
    if not project_id:
        return None
    url = f"{MR_API}/project/{urllib.parse.quote(str(project_id), safe='')}/version"
    return cached_get_json(f"versions:{project_id}", url, slim=_slim_versions)


# c020
def fetch_curseforge_by_slug(modid, api_key):
    if not modid or not _cf_ready(api_key):
        return None
    url = f"{CF_API}/mods/search?gameId=432&classId=6&slug={urllib.parse.quote(str(modid))}"
    items = cached_get_json(f"cf_slug2:{str(modid).lower()}", url, _cf_headers(api_key), slim=_slim_cf_list)
    return items[0] if items else None


def search_curseforge(display_name, api_key, modid=None):
    if not display_name or not _cf_ready(api_key):
        return None
    url = (f"{CF_API}/mods/search?gameId=432&classId=6"
           f"&searchFilter={urllib.parse.quote(str(display_name))}&pageSize=5")
    items = cached_get_json(f"cf_search2:{str(display_name).lower()}", url, _cf_headers(api_key), slim=_slim_cf_list)
    return pick_search_hit(items, display_name, modid, "name")


def fetch_curseforge_files(cf_id, api_key):
    if not cf_id or not _cf_ready(api_key):
        return None
    url = f"{CF_API}/mods/{urllib.parse.quote(str(cf_id))}/files?pageSize=50"
    return cached_get_json(f"cf_files:{cf_id}", url, _cf_headers(api_key), slim=_slim_cf_files)


def curseforge_side_from_files(files):
    # c024
    if not files:
        return None, None
    has_client_tag = False
    has_server_tag = False
    has_any_tag = False
    recent = sorted(files, key=lambda f: f.get("fileDate") or "", reverse=True)[:5]
    for f in recent:
        versions = {str(v).strip().lower() for v in (f.get("gameVersions") or [])}
        if "client" in versions:
            has_client_tag = True
            has_any_tag = True
        if "server" in versions:
            has_server_tag = True
            has_any_tag = True
    if not has_any_tag:
        return None, None
    client_side_val = "required" if has_client_tag else "unsupported"
    server_side_val = "required" if has_server_tag else "unsupported"
    return client_side_val, server_side_val


API_LOADER = "neoforge"


def leading_number(s):
    m = re.search(r"\d+", s or "")
    return int(m.group()) if m else 0


def _num_tuple(v):
    return tuple(int(x) for x in re.findall(r"\d+", v or ""))


def versions_same(a, b):
    a = (a or "").strip().lower().lstrip("v")
    b = (b or "").strip().lower().lstrip("v")
    if not a or not b:
        return False
    if a == b:
        return True
    na, nb = _num_tuple(a), _num_tuple(b)
    if len(na) > len(nb):
        na, nb = nb, na
    return len(na) >= 3 and nb[len(nb) - len(na):] == na


_QUALIFIER_RANK = {"snapshot": -4, "dev": -4, "alpha": -3, "a": -3, "beta": -2, "b": -2,
                   "pre": -1, "preview": -1, "rc": 0, "cr": 0}
_MC_PREFIX_RE = re.compile(r"^(?:mc)?1\.(?:1[6-9]|2\d)(?:\.\d+)?[-+_ ](?:[a-z]+[-+_ ])*(?=\d)")


def version_order_key(v):
#key
    s = _MC_PREFIX_RE.sub("", str(v or "").strip().lower().lstrip("v"), count=1)
    nums = []
    pre = None
    for tok in re.findall(r"\d+|[a-z]+", s):
        if tok.isdigit():
            if pre is None:
                nums.append(int(tok))
            else:
                pre = (pre[0], pre[1] + (int(tok),))
        elif pre is None and tok in _QUALIFIER_RANK:
            pre = (_QUALIFIER_RANK[tok], ())
    while nums and nums[-1] == 0:
        nums.pop()
    return (tuple(nums), 0 if pre else 1, pre if pre else (0, ()))


def compare_versions(installed, latest):
    if versions_same(installed, latest):
        return "uptodate"
    ki, kl = version_order_key(installed), version_order_key(latest)
    if ki[0] and kl[0]:
        if ki == kl:
            return "uptodate"
        if ki > kl:
            return "ahead"
    a = _MC_PREFIX_RE.sub("", str(installed or "").lower(), count=1)
    b = _MC_PREFIX_RE.sub("", str(latest or "").lower(), count=1)
    return "major" if leading_number(b) > leading_number(a) else "update"


def _target_set():
    return bool(TARGET_MC)


def _modrinth_version_matches_target(v):
    loaders = [str(x).lower() for x in (v.get("loaders") or [])]
    if API_LOADER and API_LOADER.lower() not in loaders:
        return False
    if TARGET_MC and TARGET_MC not in (v.get("game_versions") or []):
        return False
    return True


def _curseforge_file_matches_target(f):
    tags = {str(v).strip().lower() for v in (f.get("gameVersions") or [])}
    if API_LOADER and API_LOADER.lower() not in tags:
        return False
    if TARGET_MC and TARGET_MC.lower() not in tags:
        return False
    return True


def pick_modrinth_version(versions, fallback_any=False):
    versions = [v for v in (versions or []) if isinstance(v, dict)]
    ok = [v for v in versions if _modrinth_version_matches_target(v)]
    pool = ok or (versions if fallback_any else [])
    if not pool:
        return None, False
    rel = [v for v in pool if (v.get("version_type") or "release") == "release"]
    pool = rel or pool
    return max(pool, key=lambda v: v.get("date_published") or ""), bool(ok)


def pick_curseforge_file(files, fallback_any=False):
    files = [f for f in (files or []) if isinstance(f, dict)]
    ok = [f for f in files if _curseforge_file_matches_target(f)]
    pool = ok or (files if fallback_any else [])
    if not pool:
        return None, False
    rel = [f for f in pool if (f.get("releaseType") or 1) == 1]
    pool = rel or pool
    return max(pool, key=lambda f: f.get("fileDate") or ""), bool(ok)


def check_update(installed_version, modrinth_id, cf_id=None, api_key=None):
    # c031
    if not installed_version:
        return ("unknown", None, None)

    found_any_versions = False

    if modrinth_id:
        versions = fetch_modrinth_versions(modrinth_id)
        if versions:
            found_any_versions = True
            best, _ok = pick_modrinth_version(versions)
            if best:
                latest_str = best.get("version_number") or "?"
                return (compare_versions(installed_version, latest_str), latest_str, "Modrinth")

    if cf_id and _cf_ready(api_key):
        files = fetch_curseforge_files(cf_id, api_key)
        if files:
            found_any_versions = True
            best, _ok = pick_curseforge_file(files)
            if best:
                latest_str = best.get("displayName") or best.get("fileName") or "?"
                return (compare_versions(installed_version, latest_str), latest_str, "CurseForge")

    if found_any_versions:
        return ("no_match", None, None)
    return ("unknown", None, None)


def safe_jar_name(name, fallback):
    base = os.path.basename(str(name or "").replace("\\", "/"))
    if not base or base in (".", "..") or not base.lower().endswith(".jar"):
        base = os.path.basename(str(fallback or "mod").replace("\\", "/")) or "mod"
        if not base.lower().endswith(".jar"):
            base += ".jar"
    return base


def jar_modids(path):
    try:
        with zipfile.ZipFile(path) as jar:
            data = load_meta(jar, jar.namelist())
    except (zipfile.BadZipFile, OSError, KeyError, RuntimeError, zlib.error):
        return set()
    if not data or not isinstance(data.get("mods"), list):
        return set()
    return {e.get("modId") for e in data["mods"] if isinstance(e, dict) and e.get("modId")}


def download_file(url, dest_path, timeout=30, expect_modid=None):
    # c033
    tmp = dest_path + ".part"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "auto-modpacker"})
        with urllib.request.urlopen(req, timeout=timeout) as resp, open(tmp, "wb") as out_f:
            shutil.copyfileobj(resp, out_f)
        if not zipfile.is_zipfile(tmp):
            raise OSError("not a jar/zip")
        if expect_modid:
            ids = jar_modids(tmp)
            if expect_modid not in ids:
                raise OSError(f"modId mismatch: expected {expect_modid}, got {', '.join(sorted(ids)) or 'none'}")
        os.replace(tmp, dest_path)
    except (http.client.HTTPException, ValueError) as e:
        try:
            os.remove(tmp)
        except OSError:
            pass
        raise OSError(str(e))
    except BaseException:
        try:
            os.remove(tmp)
        except OSError:
            pass
        raise


def resolve_install_candidate(modid, api_key):
    # c034
    tr = T[LANG]
    name_tag = " " + tr["by_name"].strip()

    mr = fetch_modrinth(modid)
    mr_by_name = False
    if not mr:
        mr = search_modrinth(modid, modid)
        mr_by_name = bool(mr)
    mr_page = f"https://modrinth.com/mod/{mr.get('slug', modid)}" if mr else None
    if mr:
        project_id = mr.get("project_id") or mr.get("id") or mr.get("slug")
        best, ok = pick_modrinth_version(fetch_modrinth_versions(project_id), fallback_any=True)
        if best:
            files = best.get("files") or []
            primary = next((f for f in files if f.get("primary")), (files[0] if files else None))
            return {
                "modid": modid,
                "source": "Modrinth" + (name_tag if mr_by_name else ""),
                "version_label": best.get("version_number", "?"),
                "compatible": ok,
                "download_url": primary.get("url") if (primary and ok) else None,
                "filename": safe_jar_name(primary.get("filename") if primary else None, f"{modid}.jar"),
                "page_url": mr_page,
            }

    cf = None
    cf_by_name = False
    if _cf_ready(api_key):
        cf = fetch_curseforge_by_slug(modid, api_key)
        if not cf:
            cf = search_curseforge(modid, api_key, modid)
            cf_by_name = bool(cf)
    cf_page = None
    if cf:
        cf_page = (cf.get("links") or {}).get("websiteUrl") or f"https://www.curseforge.com/minecraft/mc-mods/{cf.get('slug', modid)}"
        best, ok = pick_curseforge_file(fetch_curseforge_files(cf.get("id"), api_key), fallback_any=True)
        if best:
            return {
                "modid": modid,
                "source": "CurseForge" + (name_tag if cf_by_name else ""),
                "version_label": best.get("displayName") or best.get("fileName") or "?",
                "compatible": ok,
                "download_url": best.get("downloadUrl") if ok else None,
                "filename": safe_jar_name(best.get("fileName"), f"{modid}.jar"),
                "page_url": cf_page,
            }

    if mr:
        return {"modid": modid, "source": "Modrinth" + (name_tag if mr_by_name else ""), "version_label": "?",
                "compatible": None, "download_url": None, "filename": safe_jar_name(None, f"{modid}.jar"),
                "page_url": mr_page}
    if cf:
        return {"modid": modid, "source": "CurseForge" + (name_tag if cf_by_name else ""), "version_label": "?",
                "compatible": None, "download_url": None, "filename": safe_jar_name(None, f"{modid}.jar"),
                "page_url": cf_page}
    return None


def resolve_update_download(m, installed_version, api_key):
    if not installed_version:
        return None
    modrinth_id = m.get("modrinth_id")
    cf_id = m.get("cf_id")

    if modrinth_id:
        best, _ok = pick_modrinth_version(fetch_modrinth_versions(modrinth_id))
        if best:
            latest_str = best.get("version_number") or "?"
            files = best.get("files") or []
            primary = next((f for f in files if f.get("primary")), (files[0] if files else None))
            return {
                "display": m["display"], "fname": m["fname"], "modid": m.get("modid"), "installed": installed_version,
                "latest": latest_str, "status": compare_versions(installed_version, latest_str), "source": "Modrinth",
                "download_url": primary.get("url") if primary else None,
                "filename": safe_jar_name(primary.get("filename") if primary else None, m["fname"]),
            }

    if cf_id and _cf_ready(api_key):
        best, _ok = pick_curseforge_file(fetch_curseforge_files(cf_id, api_key))
        if best:
            latest_str = best.get("displayName") or best.get("fileName") or "?"
            return {
                "display": m["display"], "fname": m["fname"], "modid": m.get("modid"), "installed": installed_version,
                "latest": latest_str, "status": compare_versions(installed_version, latest_str), "source": "CurseForge",
                "download_url": best.get("downloadUrl"),
                "filename": safe_jar_name(best.get("fileName"), m["fname"]),
            }
    return None






def make_backup_dir():
    ts = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M")
    d = os.path.join(SCRIPT_DIR, "backup", ts, "mods")
    os.makedirs(d, exist_ok=True)
    return d



def _jar_name_map(names):
    return {str(name).lower(): name for name in names}


def _manifest_attrs(jar, names):
    name_map = _jar_name_map(names)
    actual = name_map.get("meta-inf/manifest.mf")
    if not actual:
        return {}
    try:
        raw = jar.read(actual).decode("utf-8-sig", errors="replace")
    except (KeyError, zipfile.BadZipFile, RuntimeError, zlib.error):
        return {}
    raw = raw.replace("\r\n", "\n").replace("\r", "\n")
    unfolded = []
    for line in raw.split("\n"):
        if line.startswith(" ") and unfolded:
            unfolded[-1] += line[1:]
        else:
            unfolded.append(line)
    result = {}
    for line in unfolded:
        if not line or line.startswith("--") or ":" not in line:
            continue
        key, value = line.split(":", 1)
        key = key.strip().lower()
        if key:
            result[key] = value.strip()
    return result


def _meta_strings(value, out=None, depth=0):
    if out is None:
        out = []
    if depth > 12:
        return out
    if isinstance(value, str):
        out.append(value)
    elif isinstance(value, dict):
        for key, child in value.items():
            if isinstance(key, str):
                out.append(key)
            _meta_strings(child, out, depth + 1)
    elif isinstance(value, (list, tuple)):
        for child in value:
            _meta_strings(child, out, depth + 1)
    return out


def _meta_urls(values):
    found, seen = [], set()
    for value in values:
        if not isinstance(value, str):
            continue
        for raw in re.findall(r"https?://[^\s\"'<>]+", value, flags=re.I):
            url = raw.rstrip(".,;:!?)]}>")
            try:
                host = (urllib.parse.urlparse(url).hostname or "").lower()
            except ValueError:
                continue
            if not (host == "modrinth.com" or host.endswith(".modrinth.com") or
                    host == "curseforge.com" or host.endswith(".curseforge.com")):
                continue
            key = url.rstrip("/").lower()
            if key not in seen:
                seen.add(key)
                found.append(url)
    return found[:30]


def read_artifact_meta(jar, names, data=None):
    name_map = _jar_name_map(names)
    manifest = _manifest_attrs(jar, names)
    names_out, ids_out, versions_out, text_values = [], [], [], []
    for entry in (data or {}).get("mods", []) if isinstance(data, dict) else []:
        if not isinstance(entry, dict):
            continue
        mid, title, version = entry.get("modId"), entry.get("displayName"), entry.get("version")
        if isinstance(mid, str) and mid.strip() and mid not in ids_out:
            ids_out.append(mid.strip())
        if isinstance(title, str) and title.strip() and title.strip() not in names_out:
            names_out.append(title.strip())
        if version is not None and str(version).strip() and str(version).strip() not in versions_out:
            versions_out.append(str(version).strip())
        for key in ("displayURL", "updateJSONURL", "issueTrackerURL", "description", "authors", "credits"):
            value = entry.get(key)
            if isinstance(value, (str, int, float)):
                text_values.append(str(value))
            elif isinstance(value, list):
                text_values.extend(str(x) for x in value if isinstance(x, (str, int, float)))

    if isinstance(data, dict):
        text_values.extend(_meta_strings(data))

    for filename in ("fabric.mod.json", "quilt.mod.json"):
        actual = name_map.get(filename)
        if not actual:
            continue
        try:
            payload = json.loads(jar.read(actual).decode("utf-8-sig", errors="replace"), strict=False)
        except (ValueError, KeyError, RuntimeError, zlib.error):
            continue
        if not isinstance(payload, dict):
            continue
        text_values.extend(_meta_strings(payload))
        if filename == "fabric.mod.json":
            mid, title, version = payload.get("id"), payload.get("name"), payload.get("version")
            contact = payload.get("contact")
        else:
            ql = payload.get("quilt_loader") if isinstance(payload.get("quilt_loader"), dict) else {}
            meta = ql.get("metadata") if isinstance(ql.get("metadata"), dict) else {}
            mid, title, version = ql.get("id"), meta.get("name"), ql.get("version")
            contact = meta.get("contact")
            depends = ql.get("depends") if isinstance(ql.get("depends"), dict) else {}
            for key, value in depends.items():
                if key in ("minecraft", "quilt_loader") and isinstance(value, str):
                    text_values.append(value)
        if isinstance(mid, str) and mid and mid not in ids_out:
            ids_out.append(mid)
        if isinstance(title, str) and title and title not in names_out:
            names_out.append(title)
        if version is not None and str(version) not in versions_out:
            versions_out.append(str(version))
        if isinstance(contact, dict):
            text_values.extend(str(v) for v in contact.values() if isinstance(v, str))
        for key in ("description", "icon", "license", "contributors", "authors"):
            value = payload.get(key)
            if isinstance(value, str):
                text_values.append(value)
            elif isinstance(value, list):
                text_values.extend(str(x) for x in value if isinstance(x, str))
        if filename == "quilt.mod.json":
            meta = payload.get("quilt_loader", {}).get("metadata", {}) if isinstance(payload.get("quilt_loader"), dict) else {}
            if isinstance(meta, dict):
                for key in ("description", "contributors"):
                    value = meta.get(key)
                    if isinstance(value, str):
                        text_values.append(value)
                    elif isinstance(value, dict):
                        text_values.extend(str(v) for v in value.values() if isinstance(v, str))

    manifest_keys = (
        "specification-title", "specification-vendor", "specification-version",
        "implementation-title", "implementation-version", "implementation-vendor",
        "implementation-url", "specification-url", "bundle-name", "bundle-version",
        "bundle-vendor", "automatic-module-name", "url", "website", "homepage",
    )
    selected_manifest = {key: manifest[key] for key in manifest_keys if manifest.get(key)}
    for key, value in selected_manifest.items():
        if key.endswith("-title") or key in ("bundle-name", "automatic-module-name"):
            if value not in names_out:
                names_out.append(value)
        elif key.endswith("-version") and value not in versions_out:
            versions_out.append(value)
        text_values.append(value)
    for key, value in manifest.items():
        if "url" in key or "homepage" in key or "website" in key:
            text_values.append(value)
    return {
        "modids": ids_out[:30], "names": names_out[:30], "versions": versions_out[:20],
        "links": _meta_urls(text_values), "manifest": selected_manifest,
    }


def read_toml(jar, names):
    name_map = _jar_name_map(names)
    for candidate in ("META-INF/neoforge.mods.toml", "META-INF/mods.toml"):
        actual = name_map.get(candidate.lower())
        if actual:
            content = jar.read(actual).decode("utf-8", errors="ignore")
            return candidate, content
    return None, None

def parse_toml(content):
    if tomllib:
        try:
            return tomllib.loads(content)
        except Exception:
            return None
    return None

# c038
JAR_MIN_BYTES = 2048
FABRIC_JSON = "fabric.mod.json"


def _bump(nums, idx):
    nums = (list(nums) + [0] * (idx + 1))[:idx + 1]
    nums[idx] += 1
    return nums


def fabric_range(spec):
    # c039
    if isinstance(spec, list):
        if len(spec) != 1:
            return ""
        spec = spec[0]
    if not isinstance(spec, str) or "||" in spec:
        return ""
    lo = hi = None
    for tok in spec.split():
        found = re.match(r"^(>=|<=|>|<|=|~|\^)?(.*)$", tok)
        op, ver = found.group(1) or "=", found.group(2)
        clean = re.match(r"\d+(?:\.\d+)*", ver)
        if not clean:
            continue
        nums = [int(x) for x in clean.group().split(".")]
        wild = bool(re.search(r"[xX*]", ver))
        if op == ">=":
            lo = (nums, True)
        elif op == ">":
            lo = (nums, False)
        elif op == "<=":
            hi = (nums, True)
        elif op == "<":
            hi = (nums, False)
        elif op == "~":
            lo, hi = (nums, True), (_bump(nums, 1 if len(nums) > 1 else 0), False)
        elif op == "^":
            k = next((i for i, n in enumerate(nums) if n), len(nums) - 1)
            lo, hi = (nums, True), (_bump(nums, k), False)
        elif wild:
            lo, hi = (nums, True), (_bump(nums, len(nums) - 1), False)
        else:
            lo = hi = (nums, True)
    if lo is None and hi is None:
        return ""
    a = ".".join(str(x) for x in lo[0]) if lo else ""
    b = ".".join(str(x) for x in hi[0]) if hi else ""
    return ("(" if lo and not lo[1] else "[") + a + "," + b + (")" if hi and not hi[1] else "]")


def _fabric_deps(block, kind, out):
    if not isinstance(block, dict):
        return
    for dep_id, spec in block.items():
        if isinstance(dep_id, str) and dep_id:
            dep = {"modId": dep_id, "type": kind, "versionRange": fabric_range(spec), "src": "fabric"}
            if kind == "incompatible":
                dep["reason"] = "breaks " + str(spec)
            out.append(dep)


def fabric_to_data(fj):
    # c040
    if not isinstance(fj, dict) or not isinstance(fj.get("id"), str) or not fj["id"]:
        return {}
    mid = fj["id"]
    name = fj.get("name")
    version = fj.get("version")
    mods = [{"modId": mid, "displayName": name if isinstance(name, str) and name else mid,
             "version": str(version) if version is not None else None}]
    provides = fj.get("provides") if isinstance(fj.get("provides"), list) else []
    for alias in provides:
        aid = alias.get("id") if isinstance(alias, dict) else alias
        if isinstance(aid, str) and aid and aid != mid:
            mods.append({"modId": aid, "displayName": aid, "_alias": True})
    deps = []
    _fabric_deps(fj.get("depends"), "required", deps)
    _fabric_deps(fj.get("recommends"), "optional", deps)
    _fabric_deps(fj.get("breaks"), "incompatible", deps)
    _fabric_deps(fj.get("conflicts"), "discouraged", deps)
    env = fj.get("environment")
    return {"mods": mods, "dependencies": {mid: deps},
            "mixins": fj.get("mixins") if isinstance(fj.get("mixins"), list) else [],
            "_fabric_env": env if env in ("client", "server") else None}


def read_fabric(jar, names):
    actual = _jar_name_map(names).get(FABRIC_JSON)
    if not actual:
        return None
    try:
        raw = jar.read(actual).decode("utf-8-sig", errors="ignore")
        return fabric_to_data(json.loads(raw, strict=False))
    except (ValueError, KeyError, RuntimeError, zlib.error):
        return {}


def read_quilt(jar, names):
    actual = _jar_name_map(names).get("quilt.mod.json")
    if not actual:
        return None
    try:
        payload = json.loads(jar.read(actual).decode("utf-8-sig", errors="replace"), strict=False)
    except (ValueError, KeyError, RuntimeError, zlib.error):
        return {}
    if not isinstance(payload, dict):
        return {}
    ql = payload.get("quilt_loader") if isinstance(payload.get("quilt_loader"), dict) else {}
    meta = ql.get("metadata") if isinstance(ql.get("metadata"), dict) else {}
    mid = ql.get("id")
    if not isinstance(mid, str) or not mid:
        return {}
    title = meta.get("name") if isinstance(meta.get("name"), str) and meta.get("name") else mid
    version = ql.get("version")
    mods = [{"modId": mid, "displayName": title, "version": str(version) if version is not None else None}]
    depends = ql.get("depends") if isinstance(ql.get("depends"), dict) else {}
    deps = []
    for dep_id, spec in depends.items():
        if isinstance(dep_id, str) and dep_id:
            deps.append({"modId": dep_id, "type": "required", "versionRange": fabric_range(spec), "src": "quilt"})
    return {"mods": mods, "dependencies": {mid: deps}, "_quilt_env": ql.get("environment")}


def load_meta(jar, names):
    _t, content = read_toml(jar, names)
    if content:
        return parse_toml(content)
    fabric = read_fabric(jar, names)
    if fabric is not None:
        return fabric
    return read_quilt(jar, names)


def embedded_paths(jar, names):
    # c041
    found = [n for n in names if n.lower().startswith("meta-inf/jarjar/") and n.lower().endswith(".jar")]
    fabric_name = _jar_name_map(names).get(FABRIC_JSON)
    if fabric_name:
        try:
            fj = json.loads(jar.read(fabric_name).decode("utf-8-sig", errors="ignore"), strict=False)
        except (ValueError, KeyError, RuntimeError, zlib.error):
            fj = None
        jars = fj.get("jars") if isinstance(fj, dict) else None
        for item in jars if isinstance(jars, list) else []:
            path = item.get("file") if isinstance(item, dict) else None
            if isinstance(path, str) and path in names and path not in found:
                found.append(path)
    return found


def is_broken(m):
    tr = T[LANG]
    return m.get("error") in (tr["err_badzip"], tr["err_small"], tr["err_toml_parse"], tr["err_fabric_parse"])


def fabric_break_skip(dep, installed):
    # c042
    if dep.get("src") != "fabric" or not dep.get("versionRange") or not installed:
        return False
    ver = re.match(r"\d+(?:\.\d+)*", str(installed))
    return bool(ver) and version_satisfies(ver.group(), dep["versionRange"]) is False


def aternos_kind():
    kinds = {"forge": ("modrinthforge", "curseforge"), "fabric": ("modrinthfabric", "cursefabric")}
    return kinds.get((API_LOADER or "").lower(), ("modrinthneoforge", "curseneoforge"))


def loader_label():
    return {"neoforge": "NeoForge", "forge": "Forge", "fabric": "Fabric"}.get((API_LOADER or "").lower(), API_LOADER or "?")


def file_sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()

def split_jar_suffix(fname):
    if fname.endswith(".jar.disabled"):
        return fname[: -len(".jar.disabled")], ".jar.disabled"
    if fname.endswith(".jar"):
        return fname[: -len(".jar")], ".jar"
    return fname, ""

def strip_rename_tag(base):
    for tag in RENAME_TAGS:
        if base.endswith(tag):
            return base[: -len(tag)]
    return base

def list_jar_paths():
    result = []
    for fname in sorted(os.listdir(SCRIPT_DIR)):
        if fname.endswith(".jar") or fname.endswith(".jar.disabled"):
            full = os.path.join(SCRIPT_DIR, fname)
            if os.path.isfile(full):
                result.append((fname, full))
    disabled_root = os.path.join(SCRIPT_DIR, "disabled")
    if os.path.isdir(disabled_root):
        for root, _dirs, files in os.walk(disabled_root):
            for fname in sorted(files):
                if fname.endswith(".jar") or fname.endswith(".jar.disabled"):
                    full = os.path.join(root, fname)
                    rel = os.path.relpath(full, SCRIPT_DIR)
                    result.append((rel, full))
    return result

JIJ_TAG = "Jar in Jar"
MANUAL_SIDES_PATH = os.path.join(SCRIPT_DIR, ".auto_modpacker_manual_sides.json")
MANUAL_SIDES = {}
MANUAL_SIDE_VALS = {"client": ("required", "unsupported"), "server": ("unsupported", "required"), "both": ("required", "required")}


def load_manual_sides():
    try:
        with open(MANUAL_SIDES_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError):
        return {}
    if not isinstance(data, dict):
        return {}
    return {k: v for k, v in data.items() if v in MANUAL_SIDE_VALS}


def save_manual_sides():
    try:
        with open(MANUAL_SIDES_PATH, "w", encoding="utf-8") as f:
            json.dump(MANUAL_SIDES, f, ensure_ascii=False, indent=1)
    except OSError:
        pass


def scan_embedded(jar, names):
    # c044
    result = []
    for n in embedded_paths(jar, names):
        try:
            with zipfile.ZipFile(io.BytesIO(jar.read(n))) as inner:
                data = load_meta(inner, inner.namelist())
        except (zipfile.BadZipFile, KeyError, RuntimeError, OSError, zlib.error):
            continue
        mods_list = data.get("mods") if isinstance(data, dict) else None
        if not isinstance(mods_list, list):
            continue
        for entry in mods_list:
            if not isinstance(entry, dict) or entry.get("_alias"):
                continue
            mid = entry.get("modId")
            if isinstance(mid, str) and mid:
                shown = entry.get("displayName")
                ver = entry.get("version")
                result.append({"modid": mid, "display": shown if isinstance(shown, str) and shown else mid,
                               "version": ver if isinstance(ver, str) else None, "path": n})
    return result


def format_mod_lines(m, note=""):
    modid = m.get("modid") or "?"
    note_part = f" {DIM}{note}{RESET}" if note else ""
    lines = [f"-{BOLD}{m['display']}{RESET} [{modid}] [{m['fname']}]{note_part}"]
    for e in m.get("embedded") or []:
        lines.append(f"--{e['display']} [{e['modid']}] [{JIJ_TAG}]")
    return lines




def retry_unresolved(mods, internet, api_key):
    tr = T[LANG]
    purge_lookup_cache(mods)
    tty = getattr(sys.stdout, "isatty", lambda: False)()
    cols = shutil.get_terminal_size((80, 24)).columns
    if not tty:
        say(tr["manual_retry"])
    total = len(mods)
    for i, m in enumerate(mods, start=1):
        if tty:
            line = f"{tr['manual_retry']} {i}/{total}  {m['display']}"
            sys.stdout.write("\r\033[2K" + line[:max(cols - 1, 20)])
            sys.stdout.flush()
        classify_mod(m, internet, api_key)
    if tty:
        sys.stdout.write("\r\033[2K")
        sys.stdout.flush()
    resolved = sum(1 for m in mods if m.get("side_class") != "unknown")
    say(f"{tr['manual_retry_result'].format(ok=resolved, n=total)}")


def offer_manual_sides(api_key):
    tr = T[LANG]
    if not LAST_RUN or not LAST_RUN["internet"]:
        return None
    internet = LAST_RUN["internet"]
    mods = LAST_RUN["mods"]
    assigned = 0
    valid_answers = ("", "r", "c", "s", "b", "h", "q")
    while True:
        failed = [m for m in mods if not m["error"] and m.get("modid") and m.get("side_class") == "unknown"]
        if not failed:
            break
        say()
        say(f"{YELLOW}{BOLD}{tr['manual_intro'].format(n=len(failed))}{RESET}")
        say(tr["manual_legend"])
        retry = False
        quit_all = False
        for i, m in enumerate(failed, start=1):
            name = m["display"] + ((" " + tr["manual_neterr"]) if m.get("net_error") else "")
            while True:
                try:
                    ans = input(tr["manual_prompt"].format(i=i, n=len(failed), name=name, modid=m["modid"], fname=m["fname"])).strip().lower()
                except (EOFError, KeyboardInterrupt):
                    ans = "q"
                log_console_raw(f"> {ans}")
                if ans == "h":
                    say(tr["manual_help"])
                    continue
                if ans not in valid_answers:
                    continue
                break
            if ans == "r":
                retry = True
                break
            if ans == "q":
                quit_all = True
                break
            side = {"c": "client", "s": "server", "b": "both"}.get(ans)
            if side:
                MANUAL_SIDES[m["modid"]] = side
                save_manual_sides()
                apply_side(m, side, manual=True)
                assigned += 1
        if quit_all or not retry:
            break
        retry_unresolved(failed, internet, api_key)
        save_cache()
    if assigned:
        say(tr["manual_saved"].format(n=assigned))
    return None


def manifest_impl_version(jar, names):
    attrs = _manifest_attrs(jar, names)
    return attrs.get("implementation-version") or attrs.get("specification-version")


def resolve_placeholder_version(jar, names, mod_entry):
    v = mod_entry.get("version")
    if isinstance(v, str) and v.strip().startswith("${"):
        real = manifest_impl_version(jar, names)
        if real:
            mod_entry["version"] = real


def purge_lookup_cache(mods):
    # c050
    for m in mods:
        modid = m.get("modid") or ""
        disp = (m.get("display") or "").lower()
        keys = [f"proj:{modid}", f"search:{disp}", f"search2:{disp}", f"cf_slug_exact:{modid.lower()}",
                f"cf_slug2:{modid.lower()}", f"cf_search:{disp}", f"cf_search2:{disp}"]
        if m.get("modrinth_id"):
            keys.append(f"versions:{m['modrinth_id']}")
        if m.get("cf_id"):
            keys.append(f"cf_files:{m['cf_id']}")
        for key in keys:
            CACHE.pop(key, None)
    save_cache()


# c162
def scan_mods():
    mods = []
    local_modids = set()
    modid_display = {}
    modid_files = {}
    disabled_names = []
    hash_files = {}
    for fname in sorted(os.listdir(SCRIPT_DIR)):
        full = os.path.join(SCRIPT_DIR, fname)
        if not os.path.isfile(full):
            continue
        if fname.endswith(".jar.disabled"):
            disabled_names.append(fname)
            continue
        if fname.endswith((".zip", ".ja", ".rar", ".7z")):
            disabled_names.append(fname + "  (?)")
            continue
        if not fname.endswith(".jar"):
            continue
        path = full
        try:
            file_hash = file_sha256(path)
            hash_files.setdefault(file_hash, []).append(fname)
            with zipfile.ZipFile(path) as jar:
                names = jar.namelist()
                toml_name, content = read_toml(jar, names)
                if content:
                    data = parse_toml(content)
                    parse_err = T[LANG]["err_toml_parse"]
                else:
                    data = read_fabric(jar, names)
                    if data is None:
                        data = read_quilt(jar, names)
                    parse_err = T[LANG]["err_fabric_parse"]
                    if data is None:
                        artifact_meta = read_artifact_meta(jar, names)
                        small = os.path.getsize(path) < JAR_MIN_BYTES
                        mods.append({"fname": fname, "modid": None, "display": fname, "data": None, "artifact_meta": artifact_meta, "error": T[LANG]["err_small" if small else "err_toml_missing"], "sha256": file_hash})
                        continue
                artifact_meta = read_artifact_meta(jar, names, data)
                if (not data or not isinstance(data.get("mods"), list) or not data["mods"]
                        or not isinstance(data["mods"][0], dict)):
                    mods.append({"fname": fname, "modid": None, "display": fname, "data": data, "artifact_meta": artifact_meta, "error": parse_err, "sha256": file_hash})
                    continue
                mod_entry = data["mods"][0]
                modid = mod_entry.get("modId")
                if not isinstance(modid, str) or not modid.strip():
                    modid = None
                display = mod_entry.get("displayName")
                if not isinstance(display, str) or not display.strip():
                    display = modid or fname
                resolve_placeholder_version(jar, names, mod_entry)
                if mod_entry.get("version") is not None and not isinstance(mod_entry["version"], str):
                    mod_entry["version"] = str(mod_entry["version"])
                embedded = scan_embedded(jar, names)
                mods.append({"fname": fname, "modid": modid, "display": display, "data": data, "artifact_meta": artifact_meta, "error": None, "sha256": file_hash, "embedded": embedded})
                for emb in embedded:
                    local_modids.add(emb["modid"])
                    modid_display.setdefault(emb["modid"], emb["display"])
                for extra in data["mods"][1:]:
                    eid = extra.get("modId") if isinstance(extra, dict) else None
                    if isinstance(eid, str) and eid:
                        local_modids.add(eid)
                        shown = extra.get("displayName")
                        modid_display.setdefault(eid, shown if isinstance(shown, str) and shown else eid)
                if modid:
                    local_modids.add(modid)
                    modid_display.setdefault(modid, display)
                    modid_files.setdefault(modid, set()).add(fname)
        except (zipfile.BadZipFile, zlib.error, EOFError, NotImplementedError, RuntimeError, OSError):
            mods.append({"fname": fname, "modid": None, "display": fname, "data": None, "error": T[LANG]["err_badzip"], "sha256": None})

    disabled_dir = os.path.join(SCRIPT_DIR, "disabled")
    if os.path.isdir(disabled_dir):
        for root, _dirs, files in os.walk(disabled_dir):
            for fname in sorted(files):
                if fname.endswith(".jar") or fname.endswith(".jar.disabled"):
                    rel = os.path.relpath(os.path.join(root, fname), SCRIPT_DIR)
                    disabled_names.append(rel)

    identical_files = [sorted(files) for files in hash_files.values() if len(files) > 1]

    return mods, local_modids, modid_display, modid_files, disabled_names, identical_files


LAST_RUN = None
# c052


SIDE_VALID = ("required", "optional", "unsupported")
SECTION_ORDER = ("client", "server", "both", "unknown", "broken")


def side_from_vals(client_val, server_val):
    c = client_val if client_val in SIDE_VALID else None
    s = server_val if server_val in SIDE_VALID else None
    if s == "unsupported" and c != "unsupported":
        return "client"
    if c == "unsupported" and s != "unsupported":
        return "server"
    if c is None or s is None:
        return None
    return "both"


def init_side_fields(m):
    m["side_class"] = "unknown"
    m["modrinth_id"] = None
    m["cf_id"] = None
    m["cf_slug"] = None
    m["client_side"] = None
    m["server_side"] = None
    m["downloads"] = 0
    m["side_note"] = ""
    m["was_manual"] = False
    m["net_error"] = False


def apply_side(m, side, manual=False):
    m["side_class"] = side
    vals = MANUAL_SIDE_VALS.get(side)
    if manual and vals:
        m["client_side"], m["server_side"] = vals
        m["was_manual"] = True
        m["side_note"] = ""


def classify_mod(m, internet, api_key):
    # c055
    tr = T[LANG]
    init_side_fields(m)
    modid = m.get("modid")
    display = m["display"]
    err0 = NET_STATS["errors"]
    note = ""
    c_val = s_val = None
    cf_by_name = False
    listed_side = list_side_for(modid, internet)

    if internet and _cf_ready(api_key):
        src = fetch_curseforge_by_slug(modid, api_key) if modid else None
        if not src:
            src = search_curseforge(display, api_key, modid)
            cf_by_name = bool(src)
        if src:
            m["cf_id"] = src.get("id")
            m["cf_slug"] = src.get("slug")

    if internet and modid:
        mr = fetch_modrinth(modid)
        by_name = False
        if not mr:
            mr = search_modrinth(display, modid)
            by_name = bool(mr)
        if mr:
            m["modrinth_id"] = mr.get("project_id") or mr.get("id") or mr.get("slug")
            m["downloads"] = mr.get("downloads", 0) or 0
            c_val, s_val = mr.get("client_side"), mr.get("server_side")
            if by_name:
                note = tr["by_name"].strip()

    side = side_from_vals(c_val, s_val)

    if side is None and internet and m["cf_id"]:
        fb_c, fb_s = curseforge_side_from_files(fetch_curseforge_files(m["cf_id"], api_key))
        cf_side = side_from_vals(fb_c, fb_s)
        if cf_side is not None:
            c_val, s_val, side = fb_c, fb_s, cf_side
            note = ((tr["by_name"] if cf_by_name else "") + tr["cf_fallback_tag"]).strip()

    if side is None:
        env = (m.get("data") or {}).get("_fabric_env")
        if env in ("client", "server"):
            c_val, s_val = ("required", "unsupported") if env == "client" else ("unsupported", "required")
            side = side_from_vals(c_val, s_val)
            note = tr["fabric_env_tag"].strip()
    if listed_side is not None:
        side = listed_side
        listed_vals = MANUAL_SIDE_VALS.get(listed_side)
        if listed_vals:
            c_val, s_val = listed_vals
        note = tr["side_list_tag"].strip()
    m["client_side"] = c_val if c_val in SIDE_VALID else None
    m["server_side"] = s_val if s_val in SIDE_VALID else None
    m["side_note"] = note
    if side is not None:
        m["side_class"] = side
    elif modid in MANUAL_SIDES:
        apply_side(m, MANUAL_SIDES[modid], manual=True)
    m["net_error"] = NET_STATS["errors"] > err0


def bucket_of(m):
    if not m.get("error"):
        return m.get("side_class", "unknown")
    return "broken" if is_broken(m) else "unknown"


def mod_note(m):
    if m.get("was_manual"):
        return T[LANG]["manual_tag"]
    return m.get("side_note") or ""


def mod_lines(m):
    if m.get("error"):
        return [f"-{RED}{m['fname']}{RESET} [?] [{RED}{m['error']}{RESET}]"]
    return format_mod_lines(m, mod_note(m))


def section_titles():
    tr = T[LANG]
    return {"client": tr["sect_client"], "server": tr["sect_server"], "both": tr["sect_both"],
            "unknown": tr["sect_failed"], "broken": tr["sect_broken"]}


def _cut(text, width):
    return text if len(text) <= width else text[:max(width - 3, 1)] + "..."


class LiveView:
    def __init__(self, total):
        self.total = max(int(total), 1)
        self.done = 0
        self.rows = {b: [] for b in SECTION_ORDER}
        self.current = ""
        self.drawn = 0
        self.last_draw = 0.0
        try:
            self.enabled = bool(sys.stdout.isatty())
        except (AttributeError, ValueError):
            self.enabled = False

    def add(self, m):
        self.rows[bucket_of(m)].append(strip_ansi(mod_lines(m)[0]))
        self.done += 1
        self.current = ""
        self.draw()

    def build(self):
        titles = section_titles()
        cols, term_rows = shutil.get_terminal_size((80, 24))
        width = max(30, cols - 1)
        budget = max(10, term_rows - 3)
        pct = self.done * 100 // self.total
        bar_w = max(10, min(30, width - 24))
        fill = bar_w * self.done // self.total
        lines = [f"{BOLD}[{'#' * fill}{'-' * (bar_w - fill)}]{RESET} {pct:3d}%  {self.done}/{self.total}"]
        if self.current:
            lines.append(DIM + _cut(">> " + self.current, width) + RESET)
        buckets = [b for b in SECTION_ORDER if b != "broken" or self.rows["broken"]]
        left = max(budget - len(lines) - len(buckets), 0)
        quota = {}
        order = sorted(buckets, key=lambda b: len(self.rows[b]))
        for idx, b in enumerate(order):
            share = left // (len(order) - idx)
            quota[b] = min(len(self.rows[b]), share)
            left -= quota[b]
        for b in buckets:
            rows_b = self.rows[b]
            lines.append(f"{GREEN}{BOLD}§ {titles[b]} ({len(rows_b)}){RESET}")
            q = quota[b]
            if len(rows_b) > q:
                if q >= 2:
                    lines.append(DIM + f"  ... +{len(rows_b) - (q - 1)}" + RESET)
                    show = rows_b[-(q - 1):]
                else:
                    show = rows_b[-q:] if q else []
            else:
                show = rows_b
            for text in show:
                lines.append(_cut(text, width))
        return lines

    def draw(self, force=False):
        if not self.enabled:
            return
        now = time.time()
        if not force and now - self.last_draw < 0.1:
            return
        self.last_draw = now
        lines = self.build()
        buf = []
        if self.drawn:
            buf.append(f"\033[{self.drawn}A")
        for ln in lines:
            buf.append("\r\033[2K" + ln + "\n")
        buf.append("\033[J")
        sys.stdout.write("".join(buf))
        sys.stdout.flush()
        self.drawn = len(lines)

    def finish(self):
        if self.enabled and self.drawn:
            sys.stdout.write(f"\033[{self.drawn}A\r\033[J")
            sys.stdout.flush()
        self.drawn = 0


def classify_all(mods, internet, api_key):
    # c061
    live = LiveView(len(mods))
    for m in mods:
        init_side_fields(m)
    try:
        live.draw(force=True)
        for m in mods:
            if m["error"]:
                live.add(m)
        live.draw(force=True)
        checked = 0
        for m in mods:
            if m["error"]:
                continue
            live.current = m["display"]
            live.draw()
            classify_mod(m, internet, api_key)
            live.add(m)
            checked += 1
            if checked % 20 == 0:
                save_cache()
    except KeyboardInterrupt:
        live.finish()
        save_cache()
        return False
    live.finish()
    save_cache()
    return True


def dep_type_of(dep):
    t = dep.get("type")
    if isinstance(t, str) and t.strip():
        return t.strip().lower()
    if "mandatory" in dep:
        return "required" if dep.get("mandatory") else "optional"
    return "optional"


def deps_of(m):
    data = m.get("data")
    modid = m.get("modid")
    if not isinstance(data, dict) or not isinstance(modid, str) or not modid:
        return []
    table = data.get("dependencies")
    lst = table.get(modid) if isinstance(table, dict) else None
    return [d for d in lst if isinstance(d, dict)] if isinstance(lst, list) else []


# c163
def analyze_deps(mods, local_modids, modid_display):
    required_missing = {}
    optional_missing = {}
    incompatibilities = []
    reverse_deps = {}
    seen_incompat = set()
    local_versions = {}
    for m0 in mods:
        d0 = m0.get("data")
        if m0.get("error") or not d0:
            continue
        for e0 in d0.get("mods", []):
            if isinstance(e0, dict) and e0.get("modId"):
                local_versions[e0["modId"]] = e0.get("version")
    for m in mods:
        data = m.get("data")
        if m.get("error") or not data:
            continue
        deps_table = data.get("dependencies")
        if not isinstance(deps_table, dict):
            continue
        display = m["display"]
        for entry in data.get("mods", []):
            mid = entry.get("modId") if isinstance(entry, dict) else None
            dep_list = deps_table.get(mid, []) if mid else []
            if not isinstance(dep_list, list):
                continue
            for dep in dep_list:
                if not isinstance(dep, dict):
                    continue
                dep_modid = dep.get("modId")
                if not dep_modid or dep_modid == mid:
                    continue
                dep_type = dep_type_of(dep)
                if dep_type == "incompatible":
                    if dep_modid in local_modids and not fabric_break_skip(dep, local_versions.get(dep_modid)):
                        pair = frozenset((mid, dep_modid))
                        if pair not in seen_incompat:
                            seen_incompat.add(pair)
                            incompatibilities.append((display, mid, modid_display.get(dep_modid, dep_modid), dep_modid, dep.get("reason", "")))
                    continue
                if dep_type == "discouraged":
                    continue
                if dep_modid in IMPLICIT or dep_modid in local_modids:
                    if dep_modid in local_modids:
                        reverse_deps.setdefault(dep_modid, set()).add(display)
                    continue
                target = required_missing if dep_type == "required" else optional_missing
                target.setdefault(dep_modid, set()).add(display)
    return {"required_missing": required_missing, "optional_missing": optional_missing,
            "incompatibilities": incompatibilities, "reverse_deps": reverse_deps}


def build_links(mods, internet):
    links = []
    for m in mods:
        if m.get("error") or m.get("side_class") == "client":
            continue
        display = m["display"]
        mr_entry = None
        cf_entry = None
        if internet and m.get("modrinth_id"):
            mr_entry = {"source": "Modrinth", "url": f"https://aternos.org/addons/a/{aternos_kind()[0]}/{m['modrinth_id']}"}
        if m.get("cf_slug"):
            cf_entry = {"source": "CurseForge", "url": f"https://aternos.org/addons/a/{aternos_kind()[1]}/{m['cf_slug']}"}
        direct_entries = []
        if mr_entry and cf_entry:
            direct_entries = [mr_entry, cf_entry] if (m.get("downloads") or 0) > 5000 else [cf_entry, mr_entry]
        elif mr_entry:
            direct_entries = [mr_entry]
        elif cf_entry:
            direct_entries = [cf_entry]
        if direct_entries:
            direct_entries[0]["recommended"] = True
            for e in direct_entries[1:]:
                e["recommended"] = False
        search_url = f"https://aternos.org/addons/list/1/{urllib.parse.quote(display)}"
        links.append({"display": display, "modid": m.get("modid"), "direct": direct_entries, "search": search_url})
    return links


def print_sections(mods):
    titles = section_titles()
    for bucket in SECTION_ORDER:
        items = sorted((m for m in mods if bucket_of(m) == bucket), key=lambda x: x["display"].lower())
        if not items:
            continue
        out()
        out(f"{GREEN}{BOLD}§ {titles[bucket]} ({len(items)}){RESET}")
        prev_grouped = False
        for idx, m in enumerate(items):
            lines = mod_lines(m)
            grouped = len(lines) > 1
            if idx > 0 and (grouped or prev_grouped):
                out()
            for ln in lines:
                out(ln)
            prev_grouped = grouped


# c164
def run_audit(api_key):
    global REPORT_LINES, LAST_RUN
    REPORT_LINES = []
    tr = T[LANG]
    NET_STATS["errors"] = 0
    NET_STATS["cf_denied"] = False

    internet = check_internet()
    if not internet:
        out(f"{RED}{BOLD}{tr['no_internet']}{RESET}{tr['no_internet_detail']}")

    mods, local_modids, modid_display, modid_files, disabled_names, identical_files = scan_mods()
    MANUAL_SIDES.clear()
    MANUAL_SIDES.update(load_manual_sides())

    # c068
    if not classify_all(mods, internet, api_key):
        say(f"{YELLOW}{tr['run_interrupted']}{RESET}")
        return
    if NET_STATS["cf_denied"]:
        out(f"{RED}{tr['cf_denied']}{RESET}")
    if NET_STATS["errors"]:
        out(f"{YELLOW}{tr['net_errors'].format(n=NET_STATS['errors'])}{RESET}")

    deps = analyze_deps(mods, local_modids, modid_display)
    LAST_RUN = {
        "mods": mods,
        "local_modids": local_modids,
        "modid_display": modid_display,
        "modid_files": modid_files,
        "disabled_names": disabled_names,
        "identical_files": identical_files,
        "links": [],
        "reverse_deps": deps["reverse_deps"],
        "internet": internet,
        "required_missing": deps["required_missing"],
        "optional_missing": deps["optional_missing"],
        "incompatibilities": deps["incompatibilities"],
    }

    # c069
    offer_manual_sides(api_key)
    LAST_RUN["links"] = build_links(mods, internet)

    required_missing = deps["required_missing"]
    optional_missing = deps["optional_missing"]
    incompatibilities = deps["incompatibilities"]

    counts = {"client": 0, "server": 0, "both": 0, "unknown": 0, "broken": 0, "missing_toml": 0, "valid": 0}
    client_only_names = []
    snapshot = {}
    for m in mods:
        if m["error"]:
            if is_broken(m):
                counts["broken"] += 1
            elif m["error"] == tr["err_toml_missing"]:
                counts["missing_toml"] += 1
            continue
        counts["valid"] += 1
        counts[m["side_class"]] += 1
        if m["side_class"] == "client":
            client_only_names.append(m["display"])
        if m.get("modid"):
            data = m["data"]
            version = data["mods"][0].get("version") if data and data.get("mods") else None
            snapshot[m["modid"]] = {
                "display": m["display"],
                "fname": m["fname"],
                "version": version,
                "client_side": m.get("client_side"),
                "server_side": m.get("server_side"),
                "is_client_only": m["side_class"] == "client",
            }

    out()
    out(f"{GREEN}{BOLD}{tr['header_list']}{RESET}")
    print_sections(mods)

    out()
    out(f"{GREEN}{BOLD}{tr['header_client']}{RESET}")
    if not internet:
        out(tr["client_unknown_no_internet"])
    elif client_only_names:
        for name in sorted(client_only_names, key=str.lower):
            out(f"{BOLD}{name}{RESET}")
    else:
        out(tr["no_client"])

    out()
    out(f"{GREEN}{BOLD}{tr['header_required']}{RESET}")
    if required_missing:
        for dep_modid, needers in sorted(required_missing.items()):
            names = ", ".join(f"{BOLD}{n}{RESET}" for n in sorted(needers))
            out(f"{RED}{dep_modid}{RESET}, {tr['required_for']}: {names}")
    else:
        out(tr["no_required"])

    out()
    out(f"{GREEN}{BOLD}{tr['header_optional']}{RESET}")
    if optional_missing:
        for dep_modid, needers in sorted(optional_missing.items()):
            names = ", ".join(f"{BOLD}{n}{RESET}" for n in sorted(needers))
            out(f"{dep_modid}, {tr['optional_for']}: {names}")
    else:
        out(tr["no_optional"])

    out()
    out(f"{GREEN}{BOLD}{tr['header_incompatible']}{RESET}")
    if incompatibilities:
        for a_display, a_id, b_display, b_id, reason in incompatibilities:
            reason_part = f" ({reason})" if reason else ""
            out(f"{RED}{BOLD}{a_display}{RESET}{RED} [{a_id}] <-> {BOLD}{b_display}{RESET}{RED} [{b_id}]{RESET}, {tr['incompatible_note']}{reason_part}")
    else:
        out(tr["no_incompatible"])

    out()
    out(f"{GREEN}{BOLD}{tr['header_duplicates']}{RESET}")
    duplicates = [(modid, sorted(files)) for modid, files in modid_files.items() if len(files) > 1]
    if duplicates:
        for dup_modid, files in sorted(duplicates):
            out(f"{YELLOW}{BOLD}{modid_display.get(dup_modid, dup_modid)}{RESET}{YELLOW} [{dup_modid}]{RESET}: {', '.join(files)}")
    else:
        out(tr["no_duplicates"])

    out()
    out(f"{GREEN}{BOLD}{tr['header_identical']}{RESET}")
    if identical_files:
        for group in identical_files:
            out(f"{YELLOW}{' == '.join(group)}{RESET}")
    else:
        out(tr["no_identical"])

    out()
    out(f"{GREEN}{BOLD}{tr['header_disabled']}{RESET}")
    if disabled_names:
        for name in disabled_names:
            out(name)
    else:
        out(tr["no_disabled"])

    out()
    out(f"{GREEN}{BOLD}{tr['header_stats']}{RESET}")
    total_jar = sum(1 for f in os.listdir(SCRIPT_DIR) if f.endswith(".jar") and os.path.isfile(os.path.join(SCRIPT_DIR, f)))
    out(f"{tr['stats_total']}: {total_jar}")
    out(f"{tr['stats_valid']}: {counts['valid']}")
    out(f"{tr['stats_broken']}: {counts['broken']}")
    out(f"{tr['stats_missing_toml']}: {counts['missing_toml']}")
    out(f"{tr['stats_client']}: {counts['client']}")
    out(f"{tr['stats_server']}: {counts['server']}")
    out(f"{tr['stats_both']}: {counts['both']}")
    out(f"{tr['stats_unknown']}: {counts['unknown']}")
    out(f"{tr['stats_required']}: {len(required_missing)}")
    out(f"{tr['stats_optional']}: {len(optional_missing)}")
    out(f"{tr['stats_conflicts']}: {len(incompatibilities)}")
    out(f"{tr['stats_duplicates']}: {len(duplicates)}")
    out(f"{tr['stats_identical']}: {len(identical_files)}")
    out(f"{tr['stats_disabled']}: {len(disabled_names)}")
    out(f"{tr['stats_jij']}: {sum(len(m.get('embedded') or []) for m in mods)}")

    save_cache()

    # c071
    os.makedirs(LOGS_DIR, exist_ok=True)
    run_ts = int(time.time())
    date_str = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M")
    log_name = f"{run_ts}_{date_str}.log"
    snapshot_name = f"{run_ts}_{date_str}.snapshot.json"
    log_path = os.path.join(LOGS_DIR, log_name)
    snapshot_path = os.path.join(LOGS_DIR, snapshot_name)
    try:
        with open(log_path, "w", encoding="utf-8") as f:
            f.write("\n".join(REPORT_LINES))
        with open(snapshot_path, "w", encoding="utf-8") as f:
            json.dump(snapshot, f, ensure_ascii=False)
        say(f"\n[{tr['log_saved']}: {log_path}]")
    except OSError:
        pass

    say(tr["commands"])


def do_aternos():
    tr = T[LANG]
    if not LAST_RUN:
        say(tr["run_first"])
        return
    say(f"{GREEN}{BOLD}{tr['aternos_header']}{RESET}")
    links = LAST_RUN["links"]
    if not links:
        say(tr["disable_none"])
    for entry in links:
        say(f"{BOLD}{entry['display']}{RESET} [{entry['modid'] or '?'}]")
        for d in entry["direct"]:
            tag = f" {GREEN}({tr['aternos_recommended']}){RESET}" if d.get("recommended") else ""
            say(f"  {tr['direct_label']} [{d['source']}]{tag}: {d['url']}")
        say(f"  {tr['search_label']}: {entry['search']}")
        say(SEP_LINE)
    client_count = sum(1 for m in LAST_RUN["mods"] if m.get("side_class") == "client")
    if client_count:
        say(tr["aternos_footer"].format(n=client_count))
    say(tr["commands"])


def do_stats():
    tr = T[LANG]
    if not LAST_RUN:
        say(tr["run_first"])
        return
    mods = LAST_RUN["mods"]
    counts = {"client": 0, "server": 0, "both": 0, "unknown": 0, "broken": 0, "missing_toml": 0, "valid": 0}
    for m in mods:
        if m["error"]:
            if is_broken(m):
                counts["broken"] += 1
            elif m["error"] == T[LANG]["err_toml_missing"]:
                counts["missing_toml"] += 1
            continue
        counts["valid"] += 1
        counts[m.get("side_class", "unknown")] += 1
    total_jar = sum(1 for f in os.listdir(SCRIPT_DIR) if f.endswith(".jar") and os.path.isfile(os.path.join(SCRIPT_DIR, f)))
    duplicates = [f for files in LAST_RUN["modid_files"].values() if len(files) > 1 for f in [files]]
    say(f"{GREEN}{BOLD}{tr['header_stats']}{RESET}")
    say(f"{tr['stats_total']}: {total_jar}")
    say(f"{tr['stats_valid']}: {counts['valid']}")
    say(f"{tr['stats_broken']}: {counts['broken']}")
    say(f"{tr['stats_missing_toml']}: {counts['missing_toml']}")
    say(f"{tr['stats_client']}: {counts['client']}")
    say(f"{tr['stats_server']}: {counts['server']}")
    say(f"{tr['stats_both']}: {counts['both']}")
    say(f"{tr['stats_unknown']}: {counts['unknown']}")
    say(f"{tr['stats_required']}: {len(LAST_RUN['required_missing'])}")
    say(f"{tr['stats_optional']}: {len(LAST_RUN['optional_missing'])}")
    say(f"{tr['stats_conflicts']}: {len(LAST_RUN.get('incompatibilities', []))}")
    say(f"{tr['stats_duplicates']}: {len(duplicates)}")
    say(f"{tr['stats_identical']}: {len(LAST_RUN['identical_files'])}")
    say(f"{tr['stats_disabled']}: {len(LAST_RUN['disabled_names'])}")
    say(f"{tr['stats_jij']}: {sum(len(m.get('embedded') or []) for m in LAST_RUN['mods'])}")
    say(tr["commands"])


def find_mod_by_modid(modid_query):
    # c073
    if not LAST_RUN:
        return None
    q = (modid_query or "").strip().lower()
    if not q:
        return None
    mods = LAST_RUN["mods"]
    for m in mods:
        if m.get("modid") and m["modid"].lower() == q:
            return m
    for m in mods:
        if m.get("display") and m["display"].lower() == q:
            return m
    for m in mods:
        f = (m.get("fname") or "").lower()
        if f == q or f == q + ".jar":
            return m
    hits = [m for m in mods if not m.get("error") and (q in (m.get("display") or "").lower() or q in (m.get("modid") or "").lower())]
    return hits[0] if len(hits) == 1 else None


def do_explain(args, api_key):
    tr = T[LANG]
    if not args:
        say(tr["explain_usage"])
        return
    if not LAST_RUN:
        say(tr["run_first"])
        return
    m = find_mod_by_modid(args[0])
    if not m:
        say(tr["explain_not_found"])
        return

    data = m["data"]
    modid = m["modid"]
    display = m["display"]
    version = None
    if data and data.get("mods"):
        version = data["mods"][0].get("version")

    say(f"{GREEN}{BOLD}=== {display} ==={RESET}")
    say(f"{tr['explain_id']}: {modid}")
    say(f"{tr['explain_version']}: {version or '?'}")
    side_class = m.get("side_class", "unknown")
    say(f"{tr['explain_side']}: {side_class.upper()}" + (f" ({tr['manual_tag']})" if m.get("was_manual") else ""))
    say(f"{tr['explain_client']}: {m.get('client_side') or '?'}")
    say(f"{tr['explain_server']}: {m.get('server_side') or '?'}")

    say(f"{tr['explain_deps']}:")
    dep_list = deps_of(m)
    if not dep_list:
        say(tr["explain_deps_none"])
    else:
        for dep in dep_list:
            dep_modid = dep.get("modId")
            dep_type = dep_type_of(dep)
            if not dep_modid or dep_type == "incompatible":
                continue
            present = dep_modid in IMPLICIT or dep_modid in LAST_RUN["local_modids"]
            mark = f"{GREEN}+{RESET}" if present else f"{RED}×{RESET}"
            opt_tag = tr["explain_optional_tag"] if dep_type != "required" else ""
            name = LAST_RUN["modid_display"].get(dep_modid, dep_modid)
            say(f"  {mark} {name}{opt_tag}")

    say(f"{tr['explain_used_by']}:")
    users = LAST_RUN["reverse_deps"].get(modid, set()) if modid else set()
    if users:
        for u in sorted(users):
            say(f"  {u}")
    else:
        say(tr["explain_used_by_none"])

    sources = []
    if m.get("modrinth_id"):
        sources.append("Modrinth")
    if m.get("cf_slug"):
        sources.append("CurseForge")
    say(f"{tr['explain_sources']}:")
    if sources:
        for s in sources:
            say(f"  {s}")
    else:
        say(tr["explain_sources_none"])

    if LAST_RUN["internet"] and version and (m.get("modrinth_id") or m.get("cf_id")):
        status, latest, source = check_update(version, m.get("modrinth_id"), m.get("cf_id"), api_key)
        source_tag = f" [{source}]" if source else ""
        if status == "uptodate":
            say(f"{tr['explain_update']}: {GREEN}+{RESET} {tr['updates_uptodate']}{source_tag}")
        elif status == "major":
            say(f"{tr['explain_update']}: {YELLOW}!{RESET} {tr['updates_major']} ({latest}){source_tag}")
        elif status == "update":
            say(f"{tr['explain_update']}: {YELLOW}->{RESET} {tr['updates_available']} ({latest}){source_tag}")
        elif status == "ahead":
            say(f"{tr['explain_update']}: {GREEN}+{RESET} {tr['updates_ahead']} ({latest}){source_tag}")
        elif status == "no_match":
            say(f"{tr['explain_update']}: {YELLOW}!{RESET} {tr['updates_no_match'].format(mc=TARGET_MC or '?', loader=API_LOADER)}")
        else:
            say(f"{tr['explain_update']}: {tr['updates_unknown']}")
    else:
        say(f"{tr['explain_update']}: {tr['updates_unknown']}")

    say(f"{tr['explain_integrity']}: {m.get('sha256') or '?'}")

    say(f"{tr['explain_file_section']}: {m['fname']}")
    full_path = os.path.join(SCRIPT_DIR, m["fname"])
    try:
        size_mb = os.path.getsize(full_path) / (1024 * 1024)
        say(f"{tr['explain_size']}: {size_mb:.1f} MB")
        with zipfile.ZipFile(full_path) as jar:
            names = jar.namelist()
            say(f"{tr['explain_entries']}: {len(names)}")
            has_toml = any(n.endswith("mods.toml") for n in names)
            has_manifest = "META-INF/MANIFEST.MF" in names
            say(f"{tr['explain_meta']}: mods.toml {'+' if has_toml else 'x'}, MANIFEST.MF {'+' if has_manifest else 'x'}")
            has_assets = any(n.startswith("assets/") for n in names)
            has_data = any(n.startswith("data/") for n in names)
            say(f"{tr['explain_assets']}: {'+' if has_assets else 'x'}")
            say(f"{tr['explain_data']}: {'+' if has_data else 'x'}")
            class_count = sum(1 for n in names if n.endswith(".class"))
            say(f"{tr['explain_classes']}: {class_count}")
            mixins = data.get("mixins") if data else None
            mixin_count = len(mixins) if isinstance(mixins, list) else 0
            say(f"{tr['explain_mixins']}: {mixin_count}")
    except (OSError, zipfile.BadZipFile):
        pass

    say(tr["commands"])


def preview_and_confirm(tr, header_key, items):
    say(tr[header_key])
    for old, new in items:
        say(f"  {old}  ->  {new}")
    try:
        answer = input(tr["confirm_prompt"]).strip().lower()
    except EOFError:
        return False
    log_console_raw(f"> {answer}")
    return answer in ("yes", "y", "да")


def do_disable(args):
    tr = T[LANG]
    if not args or args[0] not in ("client", "server", "both"):
        say(tr["side_disable_usage"])
        return
    if not LAST_RUN:
        say(tr["run_first"])
        return
    if not LAST_RUN["internet"]:
        say(tr["side_unknown_no_run"])
        return
    side = args[0]
    targets = [m for m in LAST_RUN["mods"] if not m["error"] and m.get("side_class") == side]
    if not targets:
        say(tr["disable_none"])
        return
    items = []
    for m in targets:
        old = m["fname"]
        new = old + ".disabled"
        items.append((old, new))
    if not preview_and_confirm(tr, "disable_preview", items):
        say(tr["cancelled"])
        return
    # c074
    side_folder = {"client": "Client", "server": "Server", "both": "Both"}.get(side, "Both")
    date_str = datetime.datetime.now().strftime("%Y-%m-%d")
    dest_dir = os.path.join(SCRIPT_DIR, "disabled", side_folder, date_str)
    done = 0
    moved = set()
    for old, new in items:
        src = os.path.join(SCRIPT_DIR, old)
        tmp = os.path.join(SCRIPT_DIR, new)
        if os.path.exists(tmp):
            continue
        try:
            os.rename(src, tmp)
        except OSError:
            continue
        try:
            os.makedirs(dest_dir, exist_ok=True)
            final = os.path.join(dest_dir, new)
            if os.path.exists(final):
                final = os.path.join(dest_dir, f"{int(time.time())}_{new}")
            os.rename(tmp, final)
        except OSError:
            pass
        moved.add(old)
        done += 1
    if moved:
        LAST_RUN["mods"] = [m for m in LAST_RUN["mods"] if m["fname"] not in moved]
    say(tr["disable_done"].format(n=done))
    say(tr["disable_moved"].format(path=os.path.relpath(dest_dir, SCRIPT_DIR)))
    say(tr["commands"])


def do_enable():
    tr = T[LANG]
    targets = [f for f, _ in list_jar_paths() if f.endswith(".jar.disabled")]
    if not targets:
        say(tr["enable_none"])
        return
    items = [(f, os.path.basename(f)[: -len(".disabled")]) for f in targets]
    if not preview_and_confirm(tr, "enable_preview", items):
        say(tr["cancelled"])
        return
    done = 0
    touched_dirs = set()
    for old, new in items:
        old_full = os.path.join(SCRIPT_DIR, old)
        new_full = os.path.join(SCRIPT_DIR, new)
        if os.path.exists(new_full):
            continue
        try:
            os.rename(old_full, new_full)
            done += 1
            touched_dirs.add(os.path.dirname(old_full))
        except OSError:
            pass
    for d in sorted(touched_dirs, key=len, reverse=True):
        try:
            if d != SCRIPT_DIR and os.path.isdir(d) and not os.listdir(d):
                os.removedirs(d)
        except OSError:
            pass
    say(tr["enable_done"].format(n=done))
    say(tr["commands"])


def do_rename():
    tr = T[LANG]
    if not LAST_RUN:
        say(tr["run_first"])
        return
    tag_map = {"client": "_CLIENT", "server": "_SERVER", "both": "_BOTH", "unknown": "_UNIDENTIFIED"}
    items = []
    for m in LAST_RUN["mods"]:
        old = m["fname"]
        base, suffix = split_jar_suffix(old)
        base = strip_rename_tag(base)
        tag = tag_map.get(m.get("side_class", "unknown"), "_UNIDENTIFIED")
        new = base + tag + suffix
        if new != old:
            items.append((old, new))
    if not items:
        say(tr["disable_none"])
        return
    if not preview_and_confirm(tr, "rename_preview", items):
        say(tr["cancelled"])
        return
    by_old = {m["fname"]: m for m in LAST_RUN["mods"]}
    done = 0
    for old, new in items:
        new_full = os.path.join(SCRIPT_DIR, new)
        if os.path.exists(new_full):
            continue
        try:
            os.rename(os.path.join(SCRIPT_DIR, old), new_full)
            done += 1
            if old in by_old:
                by_old[old]["fname"] = new
        except OSError:
            pass
    say(tr["rename_done"].format(n=done))
    say(tr["commands"])


def do_unrename():
    tr = T[LANG]
    items = []
    for fname, _ in list_jar_paths():
        base, suffix = split_jar_suffix(fname)
        stripped = strip_rename_tag(base)
        if stripped != base:
            items.append((fname, stripped + suffix))
    if not items:
        say(tr["unrename_none"])
        return
    if not preview_and_confirm(tr, "unrename_preview", items):
        say(tr["cancelled"])
        return
    by_old = {m["fname"]: m for m in (LAST_RUN["mods"] if LAST_RUN else [])}
    done = 0
    for old, new in items:
        new_full = os.path.join(SCRIPT_DIR, new)
        if os.path.exists(new_full):
            continue
        try:
            os.rename(os.path.join(SCRIPT_DIR, old), new_full)
            done += 1
            if old in by_old:
                by_old[old]["fname"] = new
        except OSError:
            pass
    say(tr["unrename_done"].format(n=done))
    say(tr["commands"])


def do_remove(args):
    tr = T[LANG]
    if not args:
        say(tr["remove_usage"])
        return
    if not LAST_RUN:
        say(tr["run_first"])
        return
    m = find_mod_by_modid(args[0])
    if not m or m.get("error"):
        say(tr["remove_not_found"])
        return

    modid = m.get("modid")
    display = m["display"]
    dep_list = deps_of(m)
    dep_count = sum(1 for d in dep_list if d.get("modId") and dep_type_of(d) != "incompatible")

    # c083
    required_users = []
    optional_users = []
    if modid:
        for other in LAST_RUN["mods"]:
            if other["fname"] == m["fname"] or not other.get("data") or not other.get("modid"):
                continue
            for dep in deps_of(other):
                if dep.get("modId") != modid:
                    continue
                dep_type = dep_type_of(dep)
                if dep_type == "required":
                    required_users.append(other["display"])
                elif dep_type == "optional":
                    optional_users.append(other["display"])
    required_users = sorted(set(required_users))
    optional_users = sorted(set(optional_users))

    side_class = m.get("side_class", "unknown")
    side_label = {"client": "CLIENT", "server": "SERVER", "both": "BOTH"}.get(side_class, "UNIDENTIFIED")

    say(f"{BOLD}{display}{RESET}")
    say(f"|- {tr['remove_depended_by']}: {len(required_users)}")
    say(f"|- {tr['remove_dependencies']}: {dep_count}")
    say(f"'- {tr['remove_side_label']}: {side_label}")

    safe = len(required_users) == 0
    if safe:
        say(f"{GREEN}{tr['remove_safe_yes']}{RESET}")
    else:
        say(f"{RED}{tr['remove_safe_no']}{RESET}")
        say(tr["remove_will_break"])
        for u in required_users:
            say(f"  -> {u}")
    if optional_users:
        say(tr["remove_optional_users"])
        for u in optional_users:
            say(f"  -> {u}")
    say(f"{tr['remove_files_affected']}: 1")

    try:
        answer = input(tr["confirm_prompt"]).strip().lower()
    except EOFError:
        answer = ""
    log_console_raw(f"> {answer}")
    if answer not in ("yes", "y", "да"):
        say(tr["cancelled"])
        say(tr["commands"])
        return

    full_path = os.path.join(SCRIPT_DIR, m["fname"])
    try:
        os.remove(full_path)
        say(tr["remove_done"].format(name=display))
    except OSError as e:
        say(tr["remove_error"].format(err=e))
    say(tr["remove_rerun_hint"])
    say(tr["commands"])


def do_export(args):
    tr = T[LANG]
    if len(args) < 2 or args[0] not in ("client", "server"):
        say(tr["export_usage"])
        return
    if not LAST_RUN:
        say(tr["run_first"])
        return
    side = args[0]
    dest_arg = " ".join(args[1:])
    dest_abs = dest_arg if os.path.isabs(dest_arg) else os.path.normpath(os.path.join(SCRIPT_DIR, dest_arg))

    title = tr["export_title_server"] if side == "server" else tr["export_title_client"]
    say(f"{GREEN}{BOLD}{title}{RESET}")
    say("-" * len(title))

    included = []
    excluded_broken = []
    for m in sorted(LAST_RUN["mods"], key=lambda x: x["display"].lower()):
        if m["error"]:
            excluded_broken.append(m["fname"])
            continue
        sc = m.get("side_class", "unknown")
        keep = sc in (side, "both", "unknown")
        if keep:
            included.append(m)
            tag = f"  {YELLOW}{tr['export_unknown_tag']}{RESET}" if sc == "unknown" else ""
            say(f"{GREEN}+{RESET} {m['display']}{tag}")
        else:
            say(f"{RED}×{RESET} {m['display']}        {sc.upper()}")

    if excluded_broken:
        say(tr["export_excluded_broken"].format(names=", ".join(excluded_broken)))

    copied = 0
    try:
        os.makedirs(dest_abs, exist_ok=True)
        for m in included:
            try:
                shutil.copy2(os.path.join(SCRIPT_DIR, m["fname"]), os.path.join(dest_abs, m["fname"]))
                copied += 1
            except OSError:
                pass
    except OSError as e:
        say(f"{RED}{e}{RESET}")

    say(tr["export_copied"].format(n=copied, path=dest_abs))
    say(tr["commands"])


def find_jars_with_class(qualified_class):
    # c157
    target = qualified_class.strip().replace(".", "/") + ".class"
    found = []
    for fname, path in list_jar_paths():
        try:
            with zipfile.ZipFile(path) as jar:
                for n in jar.namelist():
                    if n.endswith(target) or n == target:
                        found.append(fname)
                        break
        except zipfile.BadZipFile:
            continue
    return found

def do_crash(args):
    tr = T[LANG]
    if not args:
        say(tr["crash_usage"])
        return
    found = find_jars_with_class(args[0])
    if not found:
        say(tr["crash_none"])
    else:
        say(f"{tr['crash_found_in']}:")
        for f in found:
            say(f"  {f}")
    say(tr["commands"])


CRASH_STACK_FRAME_RE = re.compile(r"at (?:[^\s/()]+/)*([a-zA-Z_][\w$]*(?:\.[a-zA-Z_][\w$]*)+)\.[\w$<>]+\(")
CRASH_IGNORED_PREFIXES = ("java.", "javax.", "sun.", "jdk.", "net.minecraft.", "net.minecraftforge.",
                          "net.neoforged.", "com.mojang.", "cpw.", "org.spongepowered.", "org.apache.", "it.unimi.")

def find_latest_crash_report():
    # c158
    candidates_dirs = [
        os.path.normpath(os.path.join(SCRIPT_DIR, "..", "crash-reports")),
        os.path.normpath(os.path.join(SCRIPT_DIR, "crash-reports")),
    ]
    best = None
    checked = []
    for d in candidates_dirs:
        checked.append(d)
        if not os.path.isdir(d):
            continue
        for fname in os.listdir(d):
            if not fname.lower().endswith(".txt"):
                continue
            full = os.path.join(d, fname)
            if not os.path.isfile(full):
                continue
            try:
                mtime = os.path.getmtime(full)
            except OSError:
                continue
            if best is None or mtime > best[1]:
                best = (full, mtime)
    return best, checked

def do_crashlog():
    tr = T[LANG]
    say(f"{GREEN}{BOLD}{tr['crashlog_header']}{RESET}")
    best, checked = find_latest_crash_report()
    if not best:
        say(tr["crashlog_none_dir"].format(paths=", ".join(checked)))
        say(tr["commands"])
        return

    full_path, mtime = best
    when = datetime.datetime.fromtimestamp(mtime).strftime("%Y-%m-%d %H:%M")
    say(tr["crashlog_found"].format(name=os.path.basename(full_path), when=when))

    try:
        with open(full_path, "r", encoding="utf-8", errors="replace") as f:
            text = f.read()
    except OSError as e:
        say(tr["crashlog_readerr"].format(err=e))
        say(tr["commands"])
        return

    description = None
    for line in text.splitlines():
        line = line.strip()
        if line.lower().startswith("description:"):
            description = line.split(":", 1)[1].strip()
            break
    if description:
        say(f"{tr['crashlog_description']}: {description}")
    say()

    classes = []
    for m in CRASH_STACK_FRAME_RE.finditer(text):
        cls = m.group(1)
        if cls.startswith(CRASH_IGNORED_PREFIXES):
            continue
        if cls not in classes:
            classes.append(cls)
        if len(classes) >= 15:
            break

    say(tr["crashlog_suspects_header"])
    reported = set()
    any_hit = False
    for cls in classes:
        for jar_name in find_jars_with_class(cls):
            if jar_name in reported:
                continue
            reported.add(jar_name)
            any_hit = True
            say(f"  {BOLD}{jar_name}{RESET}  ({cls})")
    if not any_hit:
        say(f"  {tr['crashlog_suspects_none']}")

    say()
    say(tr["crashlog_hint"].format(path=full_path))
    say(tr["commands"])


def do_graphic():
    tr = T[LANG]
    if not LAST_RUN:
        say(tr["run_first"])
        return
    reverse_deps = LAST_RUN["reverse_deps"]
    modid_display = LAST_RUN["modid_display"]
    all_modids = {m["modid"] for m in LAST_RUN["mods"] if m.get("modid")}
    depends_on_local = set()
    for m in LAST_RUN["mods"]:
        data = m["data"]
        modid = m["modid"]
        if not data or not modid:
            continue
        for dep in deps_of(m):
            dep_modid = dep.get("modId")
            dep_type = dep_type_of(dep)
            if dep_type != "incompatible" and dep_modid in all_modids:
                depends_on_local.add(modid)

    printed_as_child = set()
    for parent_id in sorted(reverse_deps.keys()):
        children = reverse_deps[parent_id]
        if not children:
            continue
        say(f"{BOLD}{modid_display.get(parent_id, parent_id).upper()}{RESET}")
        for child in sorted(children):
            say(f"--{child}")
            printed_as_child.add(child)
        say("")

    singles = [modid_display.get(m["modid"], m["display"]) for m in LAST_RUN["mods"]
               if m.get("modid") and m["modid"] not in reverse_deps and m["modid"] not in depends_on_local
               and modid_display.get(m["modid"], m["display"]) not in printed_as_child]
    if singles:
        say(f"{BOLD}{tr['graphic_singles']}{RESET}")
        for s in sorted(set(singles)):
            say(f"--{s}")
    say(tr["commands"])


def do_orphan():
    tr = T[LANG]
    if not LAST_RUN:
        say(tr["run_first"])
        return
    all_modids = {m["modid"] for m in LAST_RUN["mods"] if m.get("modid")}
    has_edge = set(LAST_RUN["reverse_deps"].keys())
    depends_on_local = set()
    for m in LAST_RUN["mods"]:
        data = m["data"]
        modid = m["modid"]
        if not data or not modid:
            continue
        for dep in deps_of(m):
            dep_modid = dep.get("modId")
            dep_type = dep_type_of(dep)
            if dep_type != "incompatible" and dep_modid in all_modids:
                depends_on_local.add(modid)
                has_edge.add(dep_modid)
    orphans = [m for m in LAST_RUN["mods"] if m.get("modid") and m["modid"] not in has_edge and m["modid"] not in depends_on_local]

    say(f"{GREEN}{BOLD}{tr['header_orphan']}{RESET}")
    if orphans:
        for m in sorted(orphans, key=lambda x: x["display"]):
            say(f"{BOLD}{m['display']}{RESET} [{m['modid']}] ({m['fname']})")
    else:
        say(tr["orphan_none"])
    say(tr["orphan_note"])
    say(tr["commands"])


def collect_scan_findings():
    # c159
    per_file = {}
    for fname, path in list_jar_paths():
        try:
            with zipfile.ZipFile(path) as jar:
                names = jar.namelist()
                findings = []
                for n in names:
                    low = n.lower()
                    if low.endswith(EXEC_EXT):
                        findings.append(("HIGH", "exec", n))
                    elif low.endswith(POWERSHELL_EXT):
                        findings.append(("HIGH", "powershell", n))
                    elif low.endswith(NATIVE_LIB_EXT):
                        findings.append(("MEDIUM", "native", n))
                found_net = set()
                found_dyn = set()
                unreadable = []
                for n in names:
                    if not n.endswith(".class"):
                        continue
                    if len(found_net) == len(NETWORK_SIGNATURES) and len(found_dyn) == len(DYNAMIC_LOAD_SIGNATURES):
                        break
                    try:
                        content = jar.read(n)
                    except ZIP_READ_ERRORS:
                        unreadable.append(n)  #ch
                        continue
                    for sig_bytes, sig_name in NETWORK_SIGNATURES:
                        if sig_name not in found_net and sig_bytes in content:
                            found_net.add(sig_name)
                    for sig_bytes, sig_name in DYNAMIC_LOAD_SIGNATURES:
                        if sig_name not in found_dyn and sig_bytes in content:
                            found_dyn.add(sig_name)
                if found_net:
                    findings.append(("LOW", "network", ", ".join(sorted(found_net))))
                if found_dyn:
                    findings.append(("MEDIUM", "dynload", ", ".join(sorted(found_dyn))))
                if unreadable:
                    shown = ", ".join(unreadable[:3]) + (f" (+{len(unreadable) - 3})" if len(unreadable) > 3 else "")
                    findings.append(("MEDIUM", "unreadable", shown))
                if findings:
                    per_file[fname] = findings
        except ZIP_READ_ERRORS:
            continue
    return per_file

def do_scan():
    tr = T[LANG]
    say(f"{GREEN}{BOLD}{tr['header_scan']}{RESET}")
    say(tr["scan_disclaimer"])
    say()

    per_file = collect_scan_findings()
    if not per_file:
        say(tr["scan_none"])
    else:
        order = sorted(per_file, key=lambda f: min(SEVERITY_ORDER[s] for s, _, _ in per_file[f]))
        for fname in order:
            say(f"{BOLD}{fname}{RESET}")
            for severity, label_key, detail in sorted(per_file[fname], key=lambda x: SEVERITY_ORDER[x[0]]):
                color = SEVERITY_COLOR[severity]
                label = tr[SCAN_LABEL_KEYS[label_key]]
                say(f"  {color}[{severity}]{RESET} {label}: {detail}")
            say(SEP_LINE)
    say(tr["commands"])


def do_dupres():
    tr = T[LANG]
    say(tr["dupres_scanning"])
    hash_map = {}
    for fname, path in list_jar_paths():
        try:
            with zipfile.ZipFile(path) as jar:
                for n in jar.namelist():
                    if not n.startswith("assets/") or n.endswith("/"):
                        continue
                    try:
                        content = jar.read(n)
                    except ZIP_READ_ERRORS:
                        continue
                    h = hashlib.sha256(content).hexdigest()
                    hash_map.setdefault(h, set()).add((fname, n))
        except ZIP_READ_ERRORS:
            continue

    say(f"{GREEN}{BOLD}{tr['header_dupres']}{RESET}")
    found_any = False
    first = True
    for h, entries in hash_map.items():
        mods_involved = {fname for fname, _ in entries}
        if len(mods_involved) > 1:
            found_any = True
            if not first:
                say()
            first = False
            sample_path = sorted(entries)[0][1]
            say(f"{BOLD}{sample_path}{RESET}")
            for fname in sorted(mods_involved):
                say(f"  {fname}")
    if not found_any:
        say(tr["dupres_none"])
    say(tr["commands"])


def find_junk():
    # c160
    junk = []
    seen = set()

    if LAST_RUN:
        by_modid = {}
        for m in LAST_RUN["mods"]:
            if m.get("modid") and not m["error"]:
                by_modid.setdefault(m["modid"], []).append(m)
        for modid, entries in by_modid.items():
            if len(entries) < 2:
                continue

            def _ver_key(e):
                data = e.get("data")
                v = data["mods"][0].get("version") if data and data.get("mods") else ""
                return version_order_key(v)

            entries_sorted = sorted(entries, key=_ver_key, reverse=True)
            newest_key = _ver_key(entries_sorted[0])
            for old_entry in entries_sorted[1:]:
                if _ver_key(old_entry) == newest_key:
                    continue  #IMP
                fname = old_entry["fname"]
                full = os.path.join(SCRIPT_DIR, fname)
                if os.path.isfile(full) and fname not in seen:
                    junk.append(("old_version", fname, os.path.getsize(full)))
                    seen.add(fname)

    for fname in os.listdir(SCRIPT_DIR):
        full = os.path.join(SCRIPT_DIR, fname)
        if not os.path.isfile(full) or fname in seen:
            continue
        if fname.endswith(".jar.disabled"):
            junk.append(("disabled_flat", fname, os.path.getsize(full)))
            seen.add(fname)
        elif fname.endswith(".jar.old"):
            junk.append(("jar_old", fname, os.path.getsize(full)))
            seen.add(fname)
        elif fname.lower().endswith(JUNK_TEMP_EXT):
            junk.append(("temp", fname, os.path.getsize(full)))
            seen.add(fname)

    hash_map = {}
    for fname in sorted(os.listdir(SCRIPT_DIR)):
        full = os.path.join(SCRIPT_DIR, fname)
        if os.path.isfile(full) and fname.endswith(".jar") and fname not in seen:
            try:
                h = file_sha256(full)
            except OSError:
                continue
            hash_map.setdefault(h, []).append(fname)
    for h, names in hash_map.items():
        if len(names) > 1:
            for extra in names[1:]:
                full = os.path.join(SCRIPT_DIR, extra)
                junk.append(("duplicate", extra, os.path.getsize(full)))
                seen.add(extra)

    if os.path.isdir(LOGS_DIR):
        snapshots = list_snapshots()
        if len(snapshots) > LOG_RETENTION_KEEP:
            for snap in snapshots[:-LOG_RETENTION_KEEP]:
                base = snap[: -len(".snapshot.json")]
                for fname in (snap, base + ".log"):
                    full = os.path.join(LOGS_DIR, fname)
                    rel = os.path.join("script_logs", fname)
                    if os.path.isfile(full) and rel not in seen:
                        junk.append(("old_log", rel, os.path.getsize(full)))
                        seen.add(rel)

    return junk


def do_clean(args):
    tr = T[LANG]
    say(f"{GREEN}{BOLD}{tr['clean_header']}{RESET}")
    say(tr["clean_scanning"])

    junk = find_junk()
    if not junk:
        say(tr["clean_none"])
        say(tr["commands"])
        return

    by_cat = {}
    for cat, relpath, size in junk:
        by_cat.setdefault(cat, []).append((relpath, size))

    total_size = sum(size for _, _, size in junk)
    for cat, entries in by_cat.items():
        label = tr.get(f"clean_cat_{cat}", cat)
        say(f"{BOLD}{label}{RESET} ({len(entries)}):")
        for relpath, size in entries:
            say(f"  {relpath}  ({size / 1024:.0f} KB)")
    say(tr["clean_total"].format(n=len(junk), size=total_size / (1024 * 1024)))

    try:
        answer = input(tr["confirm_prompt"]).strip().lower()
    except EOFError:
        answer = ""
    log_console_raw(f"> {answer}")
    if answer not in ("yes", "y", "да"):
        say(tr["cancelled"])
        say(tr["commands"])
        return

    date_str = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    archive_name = f"clean_{date_str}.zip"
    n_try = 1
    while os.path.exists(os.path.join(SCRIPT_DIR, archive_name)):
        n_try += 1
        archive_name = f"clean_{date_str}_{n_try}.zip"
    archive_path = os.path.join(SCRIPT_DIR, archive_name)
    archived = []
    created = False
    try:
        with zipfile.ZipFile(archive_path, "x", zipfile.ZIP_DEFLATED) as zf:
            created = True
            for _cat, relpath, _size in junk:
                full = os.path.join(SCRIPT_DIR, relpath)
                if os.path.isfile(full):
                    zf.write(full, arcname=relpath)
                    archived.append(relpath)
        with zipfile.ZipFile(archive_path) as zf:
            bad = zf.testzip()
        if bad is not None:
            raise OSError(f"{archive_name}: {bad}")
    except (OSError, zipfile.BadZipFile, zlib.error) as e:
        if created:
            try:
                os.remove(archive_path)
            except OSError:
                pass
        say(tr["clean_archive_error"].format(err=e))
        say(tr["commands"])
        return

    removed = 0
    for relpath in archived:
        full = os.path.join(SCRIPT_DIR, relpath)
        try:
            os.remove(full)
            removed += 1
        except OSError:
            pass

    say(tr["clean_done"].format(archive=archive_name, n=removed))
    say(tr["commands"])


TARGET_MC = None
TARGET_LOADER = None

def parse_maven_range(s):
    if not s:
        return None
    s = s.strip()
    if s[0] not in "[(":
        return ("min", s)
    if len(s) < 2 or s[-1] not in "])":
        return None
    low_incl = s[0] == "["
    high_incl = s[-1] == "]"
    inner = s[1:-1]
    if "," in inner:
        lo, hi = inner.split(",", 1)
    else:
        lo = hi = inner
    lo = lo.strip() or None
    hi = hi.strip() or None
    return ("range", lo, hi, low_incl, high_incl)

def version_key(v):
    parts = re.findall(r"\d+", v or "")
    return tuple(int(p) for p in parts) if parts else (0,)

def version_satisfies(version_str, range_str):
    parsed = parse_maven_range(range_str)
    if not parsed:
        return None
    vk = version_key(version_str)
    if parsed[0] == "min":
        return vk >= version_key(parsed[1])
    _, lo, hi, lo_incl, hi_incl = parsed
    if lo:
        lok = version_key(lo)
        if (vk < lok) if lo_incl else (vk <= lok):
            return False
    if hi:
        hik = version_key(hi)
        if (vk > hik) if hi_incl else (vk >= hik):
            return False
    return True

# c169
def do_version(args, api_key=None):
    global TARGET_MC, TARGET_LOADER, API_LOADER
    tr = T[LANG]
    if not args:
        if TARGET_MC:
            say(tr["version_current"].format(mc=TARGET_MC, loader=TARGET_LOADER, name=loader_label()))
        else:
            say(tr["version_none_set"])
        return
    if len(args) < 2:
        say(tr["version_usage"])
        return
    TARGET_MC, TARGET_LOADER = args[0], args[1]
    if len(args) > 2:
        API_LOADER = args[2].lower()

    say(tr["version_header"])
    say(tr["version_mc_line"].format(mc=TARGET_MC))
    say(tr["version_loader_line"].format(loader=TARGET_LOADER, name=loader_label()))
    say("")
    say(tr["version_detected"])

    if not LAST_RUN:
        say(tr["run_first"])
        return

    for m in LAST_RUN["mods"]:
        if m["error"] or not m.get("data") or not m.get("modid"):
            continue
        data = m["data"]
        modid = m["modid"]
        deps = deps_of(m)
        mc_range = None
        loader_range = None
        for dep in deps:
            if dep.get("modId") == "minecraft":
                mc_range = dep.get("versionRange")
            elif dep.get("modId") in ("neoforge", "forge", "fabricloader"):
                loader_range = dep.get("versionRange")

        ok_mc = version_satisfies(TARGET_MC, mc_range) if mc_range else None
        ok_loader = version_satisfies(TARGET_LOADER, loader_range) if loader_range else None

        if ok_mc is False:
            say(f"{m['display']:<20} {RED}×{RESET} requires {mc_range}")
        elif ok_loader is False:
            say(f"{m['display']:<20} {RED}×{RESET} requires {API_LOADER} {loader_range}")
        elif ok_mc is None and ok_loader is None:
            say(f"{m['display']:<20} {tr['version_unknown']}")
        else:
            say(f"{m['display']:<20} {GREEN}+{RESET}")

        finder_checks = []
        finder = globals().get("_AUTO_FINDER")
        if finder:
            try:
                mr_id = m.get("modrinth_id")
                if mr_id:
                    presence = finder["modrinth_loader_versions"](mr_id)
                    if presence:
                        found = any(str(loader).lower() == str(API_LOADER).lower() and TARGET_MC in versions
                                    for loader, versions in presence.items())
                        finder_checks.append(("Modrinth", found))
            except Exception:
                pass
            try:
                cf_id = m.get("cf_id")
                if cf_id and api_key:
                    presence = finder["cf_loader_versions"](cf_id, api_key)
                    if presence:
                        found = any(str(loader).lower() == str(API_LOADER).lower() and TARGET_MC in versions
                                    for loader, versions in presence.items())
                        finder_checks.append(("CurseForge", found))
            except Exception:
                pass
        if finder_checks:
            tags = [f"{name}: {GREEN + '+' + RESET if found else YELLOW + '?' + RESET}"
                    for name, found in finder_checks]
            say(f"  Auto-Finder ({TARGET_MC}/{API_LOADER}): " + " | ".join(tags))
    say(tr["commands"])


def do_updates(api_key):
    tr = T[LANG]
    if not LAST_RUN:
        say(tr["run_first"])
        return
    if not LAST_RUN["internet"]:
        say(tr["no_internet"] + tr["no_internet_detail"])
        return
    say(f"{GREEN}{BOLD}{tr['updates_header']}{RESET}")
    for m in LAST_RUN["mods"]:
        if m["error"] or not m.get("modid"):
            continue
        data = m["data"]
        version = None
        if data and data.get("mods"):
            version = data["mods"][0].get("version")
        say(SEP_LINE)
        say(f"{BOLD}{m['display']}{RESET}")
        say(f"{tr['updates_installed']}: {version or '?'}")
        status, latest, source = check_update(version, m.get("modrinth_id"), m.get("cf_id"), api_key)
        source_tag = f" [{source}]" if source else ""
        if status == "uptodate":
            say(f"{tr['updates_latest']}:    {latest}{source_tag}")
            say(f"{GREEN}+ {tr['updates_uptodate']}{RESET}")
        elif status == "update":
            say(f"{tr['updates_latest']}:    {latest}{source_tag}")
            say(f"{YELLOW}-> {tr['updates_available']}{RESET}")
        elif status == "major":
            say(f"{tr['updates_latest']}:    {latest}{source_tag}")
            say(f"{YELLOW}! {tr['updates_major']}{RESET}")
        elif status == "ahead":
            say(f"{tr['updates_latest']}:    {latest}{source_tag}")
            say(f"{GREEN}+ {tr['updates_ahead']}{RESET}")
        elif status == "no_match":
            say(f"{YELLOW}! {tr['updates_no_match'].format(mc=TARGET_MC or '?', loader=API_LOADER)}{RESET}")
        else:
            say(f"{tr['updates_unknown']}")
    say(tr["commands"])


def do_install(args, api_key):
    tr = T[LANG]
    if not args or args[0] != "missing":
        say(tr["install_usage"])
        return
    if not LAST_RUN:
        say(tr["run_first"])
        return
    if not LAST_RUN["internet"]:
        say(tr["no_internet"] + tr["no_internet_detail"])
        return
    required = LAST_RUN["required_missing"]
    if not required:
        say(tr["install_none"])
        return
    if not TARGET_MC:
        # c085
        say(tr["need_target"])
        return

    say(f"{GREEN}{BOLD}{tr['install_header']}{RESET}")
    candidates = []
    for dep_modid, needers in sorted(required.items()):
        say(f"{BOLD}{dep_modid}{RESET} ({tr['required_for']}: {', '.join(sorted(needers))})")
        info = resolve_install_candidate(dep_modid, api_key)
        if not info:
            say(f"  {RED}×{RESET} {tr['install_not_found']}")
            say(SEP_LINE)
            continue
        say(f"  {tr['install_source']}: {info['source']}")
        say(f"  {tr['install_version']}: {info['version_label']}")
        if info["compatible"] is True:
            compat_tag = f"{GREEN}+{RESET}"
        elif info["compatible"] is False:
            compat_tag = f"{RED}×{RESET}"
        else:
            compat_tag = f"{YELLOW}?{RESET}"
        say(f"  {tr['install_compat']} ({TARGET_MC or '?'}/{API_LOADER}): {compat_tag}")
        say(f"  {tr['install_page']}: {info.get('page_url', '?')}")
        if not info.get("download_url"):
            say(f"  {YELLOW}{tr['install_manual_only']}{RESET}")
        candidates.append(info)
        say(SEP_LINE)

    downloadable = [c for c in candidates if c.get("download_url")]
    if not downloadable:
        say(tr["install_nothing_to_download"])
        say(tr["commands"])
        return

    try:
        answer = input(tr["install_confirm_prompt"]).strip().lower()
    except EOFError:
        answer = ""
    log_console_raw(f"> {answer}")
    if answer not in ("yes", "y", "да"):
        say(tr["cancelled"])
        say(tr["commands"])
        return

    done = 0
    for info in downloadable:
        dest = os.path.join(SCRIPT_DIR, info["filename"])
        if os.path.exists(dest):
            say(f"  {YELLOW}!{RESET} {info['modid']}: {info['filename']}, {tr['install_exists']}")
            continue
        try:
            download_file(info["download_url"], dest, expect_modid=info["modid"])
            done += 1
            say(f"  {GREEN}+{RESET} {info['modid']} -> {info['filename']}")
        except (OSError, urllib.error.URLError) as e:
            say(f"  {RED}×{RESET} {info['modid']}: {e}")
    say(tr["install_done"].format(n=done))
    say(tr["commands"])


def do_update(args, api_key):
    tr = T[LANG]
    if not args:
        say(tr["update_usage"])
        return
    if not LAST_RUN:
        say(tr["run_first"])
        return
    if not LAST_RUN["internet"]:
        say(tr["no_internet"] + tr["no_internet_detail"])
        return
    if not TARGET_MC:
        say(tr["need_target"])
        return

    if args[0].lower() == "all":
        targets = [m for m in LAST_RUN["mods"] if not m["error"] and m.get("modid")]
    else:
        found = find_mod_by_modid(" ".join(args))
        if not found:
            say(tr["explain_not_found"])
            return
        targets = [found]

    plan = []
    for m in targets:
        data = m.get("data")
        version = data["mods"][0].get("version") if data and data.get("mods") else None
        info = resolve_update_download(m, version, api_key)
        if info and info["status"] in ("update", "major") and info.get("download_url"):
            plan.append(info)

    if not plan:
        say(tr["update_nothing"])
        say(tr["commands"])
        return

    say(f"{GREEN}{BOLD}{tr['update_plan_header']}{RESET}")
    for info in plan:
        say(f"  {BOLD}{info['display']}{RESET}: {info['installed']} -> {info['latest']} [{info['source']}]")
    say(SEP_LINE)

    try:
        answer = input(tr["update_confirm_prompt"].format(n=len(plan))).strip().lower()
    except EOFError:
        answer = ""
    log_console_raw(f"> {answer}")
    if answer not in ("yes", "y", "да"):
        say(tr["cancelled"])
        say(tr["commands"])
        return

    backup_dir = make_backup_dir()
    say(tr["update_backup_made"].format(path=os.path.relpath(backup_dir, SCRIPT_DIR)))

    done = 0
    for info in plan:
        old_path = os.path.join(SCRIPT_DIR, info["fname"])
        try:
            shutil.copy2(old_path, os.path.join(backup_dir, info["fname"]))
            new_path = os.path.join(SCRIPT_DIR, info["filename"])
            download_file(info["download_url"], new_path, expect_modid=info.get("modid"))
            if os.path.abspath(new_path) != os.path.abspath(old_path):
                os.remove(old_path)
            done += 1
            say(f"  {GREEN}+{RESET} {info['display']} -> {info['filename']}")
        except (OSError, urllib.error.URLError) as e:
            say(f"  {RED}×{RESET} {info['display']}: {e}")
    say(tr["update_done"].format(n=done))
    say(tr["update_rerun_hint"])
    say(tr["commands"])


# c165
UPDATE_STATE_PATH = os.path.join(SCRIPT_DIR, ".auto_modpacker_update.json")
UPDATE_STAGE_DIR = os.path.join(SCRIPT_DIR, "update_stage")
UPDATE_BACKUP_DIR = os.path.join(SCRIPT_DIR, "update_backup")
UPD = None
_UPD_API_KEY = None
UPD_CHANNELS = ("release", "beta", "alpha")
UPD_LOADERS = ("neoforge", "forge", "fabric", "quilt")
UPD_ZIP_ERRORS = (zipfile.BadZipFile, zlib.error, EOFError, NotImplementedError, RuntimeError, OSError, KeyError)
UPD_SUBS = ("help", "target", "channel", "near", "plan", "list", "show", "pick", "keep", "drop", "reset", "stage",
            "apply", "export", "rollback", "status", "report", "clear")
UPD_ALIASES = {"p": "plan", "l": "list", "d": "stage", "download": "stage", "a": "apply", "e": "export", "r": "rollback",
               "t": "target", "h": "help", "?": "help", "s": "status"}
UPD_MARK = {"ready": ("+", GREEN), "current": ("=", DIM), "near": ("~", YELLOW), "beta": ("b", YELLOW),
            "nofile": ("x", RED), "unknown": ("?", RED), "manual": ("!", YELLOW), "error": ("!", YELLOW),
            "broken": ("!", RED)}
UPD_PROBLEMS = ("nofile", "unknown", "manual", "error", "near", "beta", "broken")

UPD_TEXT = {
    "ru": {
        "menu_title": "=== Центр обновления сборки ===",
        "menu_hint": "Команды: plan, list, show N, pick N, keep N, drop N, reset N, stage, apply, export <папка>, rollback, status, report, target, channel, near, clear, help, q. Номер без команды покажет мод.",
        "menu_prompt": "update> ",
        "no_plan": "План ещё не создан. Команда: plan [версия] [загрузчик], например: plan 1.21.1 neoforge",
        "need_target": "Сначала задайте цель: update target <версия Minecraft> [загрузчик], например: update target 1.21.1 neoforge",
        "target_now": "Цель: Minecraft {mc}, загрузчик {loader}",
        "target_none": "Цель не задана.",
        "target_set": "Цель сохранена: Minecraft {mc}, загрузчик {loader}. Её же используют version, updates и install.",
        "target_stale": "Цель изменилась, прежний план устарел: установите plan заново.",
        "bad_mc": "Версия Minecraft выглядит неверно: {v}. Пример: 1.21.1",
        "bad_loader": "Неизвестный загрузчик: {v}. Подходят: {ok}",
        "channel_now": "Каналы версий: {ch} ({desc})",
        "channel_desc_release": "только стабильные",
        "channel_desc_beta": "стабильные и beta",
        "channel_desc_alpha": "стабильные, beta и alpha",
        "channel_bad": 'Используй: channel release | beta | alpha',
        "near_on": "Версии с тегом родительской версии ({parent}) принимаются, в списке они помечены ~. Обычно работают, но проверьте.",
        "near_off": "Принимаются только версии с точным тегом {mc}.",
        "near_no_parent": "У версии {mc} нет родительской версии, near не выполняется.",
        "near_bad": 'Используй: near on | off',
        "offline": "Нет связи с Modrinth: план построить нельзя. Прежний план, если он был, не тронут.",
        "plan_start": "Анализ модов: {n}. Цель: Minecraft {mc}, загрузчик {loader}.",
        "plan_hash": "Считаем хеши файлов для опознания на Modrinth...",
        "plan_ident": "Опознано по хешу файла на Modrinth: {found} из {n}.",
        "plan_source": "По опознанным модам сборка сейчас: Minecraft {mc}, загрузчик {loader} ({n} мод(ов)). Цель: Minecraft {tmc}, загрузчик {tloader}.",
        "plan_loader_change": "Загрузчик меняется: {a} -> {b}. Берутся только версии под {b}, у части модов такой версии может не быть.",
        "plan_progress": 'проверено {i} из {n}',
        "plan_extras": "Ищем недостающие обязательные зависимости новых версий...",
        "extra_cf_key": "Для получения этой зависимости нужен API-ключ CurseForge.",
        "plan_empty": "В папке нет jar-файлов с модами: план пуст.",
        "sum_title": "План для Minecraft {mc}, загрузчик {loader} (каналы: {ch}):",
        "sum_ready": 'будет обновлено: {n}',
        "sum_current": 'уже подходят, менять не нужно: {n}',
        "sum_near": 'только версия с тегом {parent} (включить: near on): {n}',
        "sum_beta": 'только beta/alpha (включить: channel beta): {n}',
        "sum_manual": 'есть версия, но прямой ссылки нет, требуется ручная загрузка: {n}',
        "sum_nofile": 'нет версии под цель: {n}',
        "sum_unknown": 'не найдены на Modrinth и CurseForge: {n}',
        "sum_error": 'не проверены из-за сбоя сети (повторите plan): {n}',
        "sum_broken": 'файлы не читаются: {n}',
        "sum_depgap": 'обновления, которым под цель не хватает зависимости (не запустятся): {n}',
        "sum_extras": 'новые обязательные зависимости: {n}',
        "sum_blockers": 'из них без версии под цель: {n}',
        "sum_next": "Дальше: list - список, show N - подробности, stage - скачать в update_stage, apply - применить с бэкапом или export <папка> - собрать новую папку модов.",
        "stale": "Папка модов изменилась после плана или цель сменилась. Установите plan заново.",
        "st_ready": "готово к обновлению",
        "st_current": "уже подходит",
        "st_near": "только тег родительской версии",
        "st_beta": "только beta/alpha",
        "st_nofile": "нет версии под цель",
        "st_unknown": "не найден на площадках",
        "st_manual": "нужна ручная загрузка",
        "st_error": 'сбой сети, повтори plan',
        "st_broken": "файл не читается",
        "act_keep": "оставить как есть",
        "act_drop": "убрать из сборки",
        "act_update": "обновить",
        "act_unported": "убрать (нет версии под цель)",
        "act_add": "добавить",
        "act_none": "не добавлять",
        "tag_keep": "[оставить]",
        "tag_drop": "[убрать]",
        "tag_picked": "[выбрано вручную]",
        "tag_extra": "новая зависимость, нужна: {by}",
        "tag_staged": "скачано",
        "tag_depgap": "[не хватает зависимости]",
        "unit_mb": "МБ",
        "src_hash": "по данным Modrinth",
        "src_toml": "по описанию мода (toml)",
        "show_depgap": "Не хватает под цель: {names}. Без этого обновлённый мод не запустится.",
        "apply_depgap_title": "Внимание: после обновления эти моды не запустятся без своих зависимостей:",
        "apply_depgap_line": '{name}: нужна {deps}',
        "grp_problems": 'Нужно решить:',
        "grp_ready": "Будет обновлено:",
        "grp_current": "Уже подходят:",
        "grp_extras": "Новые зависимости:",
        "grp_other": "Остальное:",
        "current_collapsed": 'уже подходят: {n} (list current - показать)',
        "list_empty": "В этой группе ничего нет.",
        "list_filter_bad": "Неизвестный фильтр: {v}. Есть: all, problems, ready, current, nofile, unknown, manual, beta, near, error, broken, extra, keep, drop",
        "no_item": "Не нашёл мод: {v}",
        "ambiguous": 'Подходит несколько модов для «{v}»: {names}. Уточните или используй номер.',
        "bad_number": "Нет мода с номером {v}",
        "need_items": "Укажите номера или названия модов: {cmd} 3 5-8 имя",
        "show_title": "=== {n}. {name} ===",
        "show_file": "Файл: {f}",
        "show_modid": "modId: {m}   установленная версия: {v}   сторона: {s}",
        "show_compat_yes": "Установленный файл уже подходит под цель ({src}).",
        "show_compat_no": "Установленный файл под цель НЕ подходит ({src}).",
        "show_src": "Источник: {src}   страница: {page}",
        "show_status": "Статус: {st}",
        "show_note": "Заметка: {note}",
        "show_chosen": "Выбрано: {ver} ({typ}) {extra}файл {fn}{size}",
        "show_cands": "Найдено под цель:",
        "show_cand_line": "  {kind:5} {typ:8} {ver}  {date}",
        "show_deps": "Обязательные зависимости новой версии: {n}",
        "show_action": "Действие при apply: {act}",
        "show_staged": "Скачано в update_stage: {f}",
        "show_stage_err": "Ошибка скачивания: {e}",
        "show_required_by": "Нужен для: {by}",
        "show_support": "У проекта есть: {s}",
        "support_line": "игра {gv}; загрузчики {ld}",
        "kind_exact": "точно",
        "kind_near": "~тег",
        "pick_none": "Для {name} нет версий под цель, выбирать не из чего.",
        "pick_title": "Версии под цель для {name}:",
        "pick_line": "  {i}. {typ:8} {ver}  {date} {kind}",
        "pick_prompt": 'Номер версии (Enter - отмена):',
        "pick_done": "Выбрано вручную: {name} -> {ver}",
        "mark_done": "{cmd}: {n} мод(ов).",
        "reset_all_done": 'Все ручные выбор и отметки сброшены.',
        "stage_start": "Скачивание в {dir}: файлов {n}{size}",
        "stage_ok": "  + {name} -> {fn}",
        "stage_skip": '= {name}: уже скачан',
        "stage_fail": "  x {name}: {e}",
        "stage_done": "Скачано: {ok}, уже было: {had}, ошибок: {bad}.",
        "stage_nothing": "Скачивать нечего: нет модов в статусе «будет обновлено».",
        "stage_hash_bad": "хеш файла не совпал с площадкой, файл удалён",
        "stage_dup": "такой мод уже есть в сборке ({ids}), файл удалён",
        "stage_next": "Дальше: apply - применить с бэкапом или export <папка> - собрать новую папку.",
        "apply_title": "К применению:",
        "apply_update": 'заменить файл новой версией: {n}',
        "apply_add": 'добавить новые зависимости: {n}',
        "apply_drop": 'убрать в бэкап (по твоей отметке drop): {n}',
        "apply_unported": 'убрать в бэкап (нет версии под цель, иначе сборка не запустится): {n}',
        "apply_keep": 'оставить как есть: {n}',
        "apply_names": "    {names}",
        "apply_not_staged": 'Не скачано файлов: {n}. Попробовать скачать сейчас? (no - применить без них) (yes/no):',
        "apply_unstaged": 'останутся как есть, потому что не скачаны: {n}',
        "apply_skipped_unstaged": 'пропущен (не скачан): {name}',
        "apply_confirm": 'Применить? Старые файлы уйдут в {dir}, откат: rollback. (yes/no):',
        "apply_cancel": "Отменено, ничего не изменено.",
        "apply_nothing": "Применять нечего.",
        "apply_changed": 'пропущен (файл изменился после плана): {name}',
        "apply_conflict": 'пропущен (имя {fn} уже занято другим файлом): {name}',
        "apply_ok_update": "  + {old} -> {new}",
        "apply_ok_drop": '- {old} (в бэкап)',
        "apply_ok_add": '+ {new} (новая зависимость)',
        "apply_err": "  x {name}: {e}",
        "apply_done": "Готово: заменено {u}, добавлено {a}, убрано {d}, ошибок {e}. Бэкап: {dir}",
        "apply_hint": "Теперь запустите run, чтобы проверить сборку заново. Откат: update rollback.",
        "export_usage": "Используйте: export <папка> [client|server]. Папка создастся, старая сборка не изменится.",
        "export_bad_dir": "Эту папку использовать нельзя: {d}",
        "export_not_empty": 'Папка {d} не пустая, файлы будут добавлены к существующим. Продолжить? (yes/no):',
        "export_start": "Собираем новую папку модов: {d}",
        "export_done": "Скопировано: {n} (из них новых версий {u}). Пропущено: {s}. Старая сборка не тронута.",
        "export_skip_unstaged": "  пропущен (не скачан): {name}",
        "export_hint": 'Укажите эту папку как mods новой сборки. Не скачано или пропущено - смотри в list.',
        "rollback_none": "Нет применений, которые можно откатить.",
        "rollback_title": "Откат применения {stamp}: вернуть {n} файлов.",
        "rollback_confirm": 'Откатить? (yes/no):',
        "rollback_ok": '+ вернул {name}',
        "rollback_removed": '- убрал новый {name}',
        "rollback_skip": 'пропущен: {name} ({why})',
        "rollback_done": "Откат завершён: возвращено {n}, пропущено {s}.",
        "report_done": "Отчёт сохранён: {f}",
        "report_fail": "Не удалось записать отчёт: {e}",
        "clear_confirm": 'Удалить план и скачанные файлы из update_stage? Бэкапы останутся. (yes/no):',
        "clear_done": "План и скачанные файлы удалены.",
        "status_title": "=== Состояние обновления ===",
        "status_plan": "План: {when}, цель {mc} ({loader}), каналы: {ch}, near: {near}",
        "status_staged": "Скачано: {n} из {m}",
        "status_applied": "Последнее применение: {stamp}",
        "status_none": "План не создан.",
        "status_rollback": "Откат доступен: update rollback ({stamp})",
        "err_cmd": 'Команда update {cmd} не выполнилась: {e}',
        "unknown_sub": "Неизвестная подкоманда: {v}. Список: update help",
        "help": ('Центр обновления сборки: перенос модов на другую версию Minecraft.',
                 'Порядок: target -> plan -> list/show/pick/keep/drop -> stage -> apply (или export).',
                 'update                     открыть интерфейс (команды те же без слова update)',
                 'update target <mc> [загр.] задать цель, например 1.21.1 neoforge',
                 'update plan [mc] [загр.]   проанализировать все моды под цель (сеть). fresh - без кэша',
                 'update list [фильтр]       список: problems, ready, current, nofile, unknown, extra, all',
                 'update show <N|имя>        подробности и найденные версии',
                 'update pick <N|имя>        выбрать версию вручную (в том числе beta)',
                 'update keep|drop|reset <N...>  оставить мод как есть, убрать из сборки, вернуть автоматику',
                 'update channel release|beta|alpha   какие версии брать',
                 'update near on|off         принимать тег родительской версии (1.21 для 1.21.1)',
                 'update stage               скачать выбранное в update_stage (проверка хеша и modId)',
                 'update apply               применить: старое в бэкап, новое в папку модов',
                 'update export <папка> [client|server]   собрать новую папку модов, старая не меняется',
                 'update rollback            откатить последнее применение',
                 "  update status | report | clear",
                 'update all | update <мод>  старый режим: обновить внутри текущей цели'),
    },
    "en": {
        "menu_title": "=== Modpack update center ===",
        "menu_hint": "Commands: plan, list, show N, pick N, keep N, drop N, reset N, stage, apply, export <folder>, rollback, status, report, target, channel, near, clear, help, q. A bare number shows a mod.",
        "menu_prompt": "update> ",
        "no_plan": "No plan yet. Command: plan [version] [loader], for example: plan 1.21.1 neoforge",
        "need_target": "Set the target first: update target <Minecraft version> [loader], for example: update target 1.21.1 neoforge",
        "target_now": "Target: Minecraft {mc}, loader {loader}",
        "target_none": "No target set.",
        "target_set": "Target saved: Minecraft {mc}, loader {loader}. version, updates and install use it too.",
        "target_stale": "The target has changed, so the previous plan is outdated. Run plan again.",
        "bad_mc": "The Minecraft version looks wrong: {v}. Example: 1.21.1",
        "bad_loader": "Unknown loader: {v}. Allowed: {ok}",
        "channel_now": "Version channels: {ch} ({desc})",
        "channel_desc_release": "stable only",
        "channel_desc_beta": "stable and beta",
        "channel_desc_alpha": "stable, beta and alpha",
        "channel_bad": 'Usage: channel release | beta | alpha',
        "near_on": "Versions tagged with the parent version ({parent}) are accepted and marked ~ in the list. They usually work, but should still be checked.",
        "near_off": "Only versions with the exact tag {mc} are accepted.",
        "near_no_parent": "Version {mc} has no parent version, so near cannot be applied.",
        "near_bad": 'Usage: near on | off',
        "offline": "Modrinth is unreachable: cannot build a plan. The previous plan, if any, is untouched.",
        "plan_start": "Analysing mods: {n}. Target: Minecraft {mc}, loader {loader}.",
        "plan_hash": "Calculating file hashes to identify mods on Modrinth...",
        "plan_ident": "Identified by file hash on Modrinth: {found} of {n}.",
        "plan_source": "By the identified mods the pack is now: Minecraft {mc}, loader {loader} ({n} mod(s)). Target: Minecraft {tmc}, loader {tloader}.",
        "plan_loader_change": "The loader changes: {a} -> {b}. Only versions for {b} are taken, some mods may have none.",
        "plan_progress": 'checked {i} of {n}',
        "plan_extras": "Looking for missing required dependencies of the new versions...",
        "extra_cf_key": "A CurseForge API key is required to resolve this dependency.",
        "plan_empty": "There are no mod jar files in the folder: the plan is empty.",
        "sum_title": "Plan for Minecraft {mc}, loader {loader} (channels: {ch}):",
        "sum_ready": 'will be updated: {n}',
        "sum_current": 'already fit; no changes needed: {n}',
        "sum_near": 'only a version tagged {parent} (enable: near on): {n}',
        "sum_beta": 'only beta/alpha (enable: channel beta): {n}',
        "sum_manual": 'a version exists, but no direct download link is available; manual download required: {n}',
        "sum_nofile": 'no version for the target: {n}',
        "sum_unknown": 'not found on Modrinth or CurseForge: {n}',
        "sum_error": 'not checked due to a network error (run plan again): {n}',
        "sum_broken": 'unreadable files: {n}',
        "sum_depgap": 'updates missing a dependency required for the target (will not start): {n}',
        "sum_extras": 'new required dependencies: {n}',
        "sum_blockers": 'of them without a version for the target: {n}',
        "sum_next": "Next: list - the list, show N - details, stage - download to update_stage, apply - apply with a backup, or export <folder> - build a new mods folder.",
        "stale": "The mods folder or target changed after the plan. Run plan again.",
        "st_ready": "ready to update",
        "st_current": "already fits",
        "st_near": "only the parent version tag",
        "st_beta": "only beta/alpha",
        "st_nofile": "no version for the target",
        "st_unknown": "not found on the platforms",
        "st_manual": "manual download needed",
        "st_error": 'network error, run plan again',
        "st_broken": "file is unreadable",
        "act_keep": "keep as is",
        "act_drop": "remove from the pack",
        "act_update": "update",
        "act_unported": "remove (no version for the target)",
        "act_add": "add",
        "act_none": "do not add",
        "tag_keep": "[keep]",
        "tag_drop": "[remove]",
        "tag_picked": "[picked by hand]",
        "tag_extra": "new dependency, needed by: {by}",
        "tag_staged": "downloaded",
        "tag_depgap": "[dependency missing]",
        "unit_mb": "MB",
        "src_hash": "by Modrinth data",
        "src_toml": "by the mod description (toml)",
        "show_depgap": "Missing for the target: {names}. The updated mod will not start without it.",
        "apply_depgap_title": "Warning: after the update these mods will not start without their dependencies:",
        "apply_depgap_line": '{name}: needs {deps}',
        "grp_problems": 'Decision required:',
        "grp_ready": "Will be updated:",
        "grp_current": "Already fit:",
        "grp_extras": "New dependencies:",
        "grp_other": "Other:",
        "current_collapsed": 'already fit: {n} (list current - show them)',
        "list_empty": "Nothing in this group.",
        "list_filter_bad": "Unknown filter: {v}. Available: all, problems, ready, current, nofile, unknown, manual, beta, near, error, broken, extra, keep, drop",
        "no_item": "Mod not found: {v}",
        "ambiguous": 'Several mods match "{v}": {names}. Please clarify or use the number.',
        "bad_number": "There is no mod number {v}",
        "need_items": "Enter mod numbers or names: {cmd} 3 5-8 name",
        "show_title": "=== {n}. {name} ===",
        "show_file": "File: {f}",
        "show_modid": "modId: {m}   installed version: {v}   side: {s}",
        "show_compat_yes": "The installed file already fits the target ({src}).",
        "show_compat_no": "The installed file does NOT fit the target ({src}).",
        "show_src": "Source: {src}   page: {page}",
        "show_status": "Status: {st}",
        "show_note": "Note: {note}",
        "show_chosen": "Chosen: {ver} ({typ}) {extra}file {fn}{size}",
        "show_cands": "Found for the target:",
        "show_cand_line": "  {kind:5} {typ:8} {ver}  {date}",
        "show_deps": "Required dependencies of the new version: {n}",
        "show_action": "Action on apply: {act}",
        "show_staged": "Downloaded to update_stage: {f}",
        "show_stage_err": "Download error: {e}",
        "show_required_by": "Needed by: {by}",
        "show_support": "The project has: {s}",
        "support_line": "game {gv}; loaders {ld}",
        "kind_exact": "exact",
        "kind_near": "~tag",
        "pick_none": "{name} has no versions for the target, nothing to pick from.",
        "pick_title": "Versions for the target of {name}:",
        "pick_line": "  {i}. {typ:8} {ver}  {date} {kind}",
        "pick_prompt": 'Version number (Enter - cancel):',
        "pick_done": "Picked by hand: {name} -> {ver}",
        "mark_done": "{cmd}: {n} mod(s).",
        "reset_all_done": 'All manual choices and marks have been cleared.',
        "stage_start": "Downloading {n} files to {dir}{size}",
        "stage_ok": "  + {name} -> {fn}",
        "stage_skip": '= {name}: already downloaded',
        "stage_fail": "  x {name}: {e}",
        "stage_done": "Downloaded: {ok}, already there: {had}, errors: {bad}.",
        "stage_nothing": "Nothing to download: no mods in the \"will be updated\" status.",
        "stage_hash_bad": "the file hash does not match the platform, the file was removed",
        "stage_dup": "this mod is already in the pack ({ids}), the file was removed",
        "stage_next": "Next: apply - apply with a backup, or export <folder> - build a new folder.",
        "apply_title": "To be applied:",
        "apply_update": 'replace the file with a new version: {n}',
        "apply_add": 'add new dependencies: {n}',
        "apply_drop": 'move to the backup (based on your drop selection): {n}',
        "apply_unported": 'move to the backup (no version for the target, otherwise the pack will not start): {n}',
        "apply_keep": 'keep as is: {n}',
        "apply_names": "    {names}",
        "apply_not_staged": 'Files not downloaded: {n}. Try to download them now? (no - apply without them) (yes/no):',
        "apply_unstaged": 'stay as they are because they were not downloaded: {n}',
        "apply_skipped_unstaged": 'skipped (not downloaded): {name}',
        "apply_confirm": 'Apply? Old files will be moved to {dir}; undo with rollback. (yes/no):',
        "apply_cancel": "Cancelled, nothing changed.",
        "apply_nothing": "Nothing to apply.",
        "apply_changed": 'skipped (the file changed after the plan): {name}',
        "apply_conflict": 'skipped (the name {fn} is already used by another file): {name}',
        "apply_ok_update": "  + {old} -> {new}",
        "apply_ok_drop": '- {old} (in backup)',
        "apply_ok_add": '+ {new} (new dependency)',
        "apply_err": "  x {name}: {e}",
        "apply_done": "Done: replaced {u}, added {a}, removed {d}, errors {e}. Backup: {dir}",
        "apply_hint": "Run the scan again to check the pack. To undo these changes, use update rollback.",
        "export_usage": "Usage: export <folder> [client|server]. The folder will be created; the old pack will remain unchanged.",
        "export_bad_dir": "This folder cannot be used: {d}",
        "export_not_empty": 'Folder {d} is not empty; files will be added to the existing contents. Continue? (yes/no):',
        "export_start": "Building a new mods folder: {d}",
        "export_done": "Copied: {n} (new versions among them: {u}). Skipped: {s}. The old pack is untouched.",
        "export_skip_unstaged": "  skipped (not downloaded): {name}",
        "export_hint": 'Set this folder as the mods folder for the new pack. For files not downloaded or skipped, see list.',
        "rollback_none": "There are no applies to undo.",
        "rollback_title": "Undo apply {stamp}: restore {n} files.",
        "rollback_confirm": 'Undo? (yes/no):',
        "rollback_ok": '+ restored {name}',
        "rollback_removed": '- removed the new {name}',
        "rollback_skip": 'skipped: {name} ({why})',
        "rollback_done": "Undo finished: restored {n}, skipped {s}.",
        "report_done": "Report saved: {f}",
        "report_fail": "Could not write the report: {e}",
        "clear_confirm": 'Delete the plan and downloaded files from update_stage? Backups will remain. (yes/no):',
        "clear_done": "The plan and downloaded files are deleted.",
        "status_title": "=== Update state ===",
        "status_plan": "Plan: {when}, target {mc} ({loader}), channels: {ch}, near: {near}",
        "status_staged": "Downloaded: {n} of {m}",
        "status_applied": "Last apply: {stamp}",
        "status_none": "No plan yet.",
        "status_rollback": "Undo is available: update rollback ({stamp})",
        "err_cmd": 'Command update {cmd} could not be executed: {e}',
        "unknown_sub": "Unknown subcommand: {v}. List: update help",
        "help": ('Modpack update center: move mods to another Minecraft version.', 'Order: target -> plan -> list/show/pick/keep/drop -> stage -> apply (or export).', 'update                     open the interface (same commands without the word update)', 'update target <mc> [loader] set the target, for example 1.21.1 neoforge', 'update plan [mc] [loader]   analyse all mods for the target (network). fresh - ignore the cache', 'update list [filter]       list: problems, ready, current, nofile, unknown, extra, all', 'update show <N|name>       details and available versions', 'update pick <N|name>       choose a version manually (including beta)', 'update keep|drop|reset <N...>  keep a mod as is, remove it from the pack, or restore automatic selection', 'update channel release|beta|alpha   which versions to use', 'update near on|off         accept the parent version tag (1.21 for 1.21.1)', 'update stage               download the selected files to update_stage (hash and modId checks)', 'update apply               apply: move old files to backup, new files to the mods folder', 'update export <folder> [client|server]   build a new mods folder without changing the old pack', 'update rollback            undo the last apply', '  update status | report | clear', 'update all | update <mod>  old mode: update within the current target'),
    },
}


def upd_t(key, **kw):
    table = UPD_TEXT["ru" if LANG == "ru" else "en"]
    text = table.get(key, UPD_TEXT["ru"].get(key, key))
    return text.format(**kw) if kw and isinstance(text, str) else text


def upd_ask(prompt):
    try:
        answer = input(prompt).strip()
    except (EOFError, ValueError):
        answer = ""
    log_console_raw(f"> {answer}")
    return answer


def upd_confirm(prompt):
    return upd_ask(prompt).lower() in ("yes", "y", "да")


def upd_now():
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def upd_cut(text, n):
    text = str(text or "")
    return text if len(text) <= n else text[: max(n - 3, 1)] + "..."


def upd_new_plan(mc, loader):
    return {"v": 1, "target": {"mc": mc, "loader": loader}, "channel": "release", "near": False,
            "created": upd_now(), "planned": None, "planned_target": None, "stale": False, "applied": None,
            "source": None, "local_modids": [], "items": []}


def upd_clean_item(it):
    if not isinstance(it, dict) or not isinstance(it.get("key"), str) or not it["key"]:
        return None
    out = dict(it)
    for k in ("display", "modid", "installed", "note", "sha256", "src", "page", "stage_error", "staged", "staged_sha256",
              "staged_for", "inst_date", "side", "compat_src"):
        if out.get(k) is not None and not isinstance(out[k], str):
            out[k] = str(out[k])
    for k in ("extra", "ident"):
        out[k] = bool(out.get(k))
    if out.get("compat") not in (True, False, None):
        out["compat"] = None
    if out.get("action") not in ("auto", "keep", "drop"):
        out["action"] = "auto"
    if out.get("state") not in ("resolved", "unknown", "broken", "error"):
        out["state"] = "unknown"
    pool = out.get("pool") if isinstance(out.get("pool"), dict) else {}
    out["pool"] = {"exact": pool.get("exact") if isinstance(pool.get("exact"), dict) else {},
                   "near": pool.get("near") if isinstance(pool.get("near"), dict) else {}}
    out["picked"] = out.get("picked") if isinstance(out.get("picked"), dict) else None
    out["required_by"] = [str(x) for x in out.get("required_by") or [] if isinstance(x, (str, int))]
    out["staged_modids"] = [str(x) for x in out.get("staged_modids") or [] if isinstance(x, str)]
    return out


def upd_validate(data):
    if not isinstance(data, dict) or data.get("v") != 1:
        return None
    target = data.get("target")
    if not isinstance(target, dict) or not isinstance(target.get("mc"), str) or not isinstance(target.get("loader"), str):
        return None
    plan = upd_new_plan(target["mc"], target["loader"])
    if data.get("channel") in UPD_CHANNELS:
        plan["channel"] = data["channel"]
    plan["near"] = bool(data.get("near"))
    for k in ("created", "planned", "applied"):
        if isinstance(data.get(k), str):
            plan[k] = data[k]
    plan["stale"] = bool(data.get("stale"))
    src = data.get("source")
    if isinstance(src, dict) and isinstance(src.get("mc"), str) and isinstance(src.get("loader"), str):
        plan["source"] = {"mc": src["mc"], "loader": src["loader"], "n": src["n"] if isinstance(src.get("n"), int) else 0}
    pt = data.get("planned_target")
    if isinstance(pt, list) and len(pt) == 2 and all(isinstance(x, str) for x in pt):
        plan["planned_target"] = pt
    plan["local_modids"] = [x for x in data.get("local_modids") or [] if isinstance(x, str)]
    items = [upd_clean_item(it) for it in data.get("items") or []]
    plan["items"] = [it for it in items if it]
    return plan


def upd_load():
    global UPD
    if UPD is not None:
        return UPD
    try:
        with open(UPDATE_STATE_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, ValueError):
        return None
    UPD = upd_validate(data)
    return UPD


def upd_save():
    if UPD is None:
        return
    tmp = UPDATE_STATE_PATH + ".tmp"
    try:
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(UPD, f, ensure_ascii=False)
        os.replace(tmp, UPDATE_STATE_PATH)
    except OSError as e:
        say(f"{RED}{e}{RESET}")


def upd_need_plan():
    plan = upd_load()
    if not plan or not plan["items"]:
        say(upd_t("no_plan"))
        return None
    return plan


def upd_stage_dir(plan):
    return os.path.join(UPDATE_STAGE_DIR, f"{plan['target']['mc']}_{plan['target']['loader']}")


def http_post_json(url, body, headers=None, timeout=30):
    hdrs = {"User-Agent": "auto-modpacker", "Content-Type": "application/json"}
    if headers:
        hdrs.update(headers)
    payload = json.dumps(body).encode("utf-8")
    for attempt in range(HTTP_RETRIES + 1):
        try:
            req = urllib.request.Request(url, data=payload, headers=hdrs, method="POST")
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return "ok", json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return "notfound", None
            if (e.code == 429 or e.code >= 500) and attempt < HTTP_RETRIES:
                try:
                    wait = int(e.headers.get("Retry-After", "2"))
                except (AttributeError, TypeError, ValueError):
                    wait = 2
                time.sleep(min(max(wait, 1), 10))
                continue
            break
        except (OSError, ValueError, http.client.HTTPException):
            if attempt < HTTP_RETRIES:
                time.sleep(1 + attempt)
                continue
            break
    NET_STATS["errors"] += 1
    return "error", None


def upd_hash_file(path, algo):
    h = hashlib.new(algo)
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest().lower()


def upd_toml_kinds(path):
    try:
        with zipfile.ZipFile(path) as jar:
            names = set(jar.namelist())
    except UPD_ZIP_ERRORS:
        return False, False
    return "META-INF/neoforge.mods.toml" in names, "META-INF/mods.toml" in names


def upd_identify(paths):
    sha_by_key = {}
    for key, path in paths.items():
        try:
            sha_by_key[key] = upd_hash_file(path, "sha1")
        except OSError:
            continue
    found = {}
    hashes = sorted(set(sha_by_key.values()))
    by_hash = {}
    for i in range(0, len(hashes), 100):
        status, data = http_post_json(f"{MR_API}/version_files", {"hashes": hashes[i:i + 100], "algorithm": "sha1"})
        if status != "ok" or not isinstance(data, dict):
            continue
        for h, v in data.items():
            if not isinstance(h, str) or not isinstance(v, dict) or not isinstance(v.get("project_id"), str):
                continue
            files = [f for f in (v.get("files") or []) if isinstance(f, dict)]
            if files and not any(isinstance(f.get("hashes"), dict) and str(f["hashes"].get("sha1", "")).lower() == h.lower() for f in files):
                continue
            by_hash[h.lower()] = {"project_id": v["project_id"], "version_number": v.get("version_number"),
                                  "game_versions": [g for g in (v.get("game_versions") or []) if isinstance(g, str)],
                                  "loaders": [g for g in (v.get("loaders") or []) if isinstance(g, str)],
                                  "date_published": v.get("date_published") if isinstance(v.get("date_published"), str) else None}
    for key, h in sha_by_key.items():
        if h in by_hash:
            found[key] = by_hash[h]
    return found


def upd_parent_mc(mc):
    parts = str(mc).split(".")
    return ".".join(parts[:-1]) if len(parts) >= 3 else None


def _upd_slim_versions(d):
    if not isinstance(d, list):
        return d
    result = []
    for v in d:
        if not isinstance(v, dict):
            continue
        files = []
        for f in v.get("files") or []:
            if isinstance(f, dict):
                hs = f.get("hashes") if isinstance(f.get("hashes"), dict) else {}
                files.append({"url": f.get("url"), "filename": f.get("filename"), "primary": f.get("primary"),
                              "size": f.get("size"), "hashes": {"sha1": hs.get("sha1"), "sha512": hs.get("sha512")}})
        deps = [{"project_id": x.get("project_id"), "dependency_type": x.get("dependency_type")}
                for x in (v.get("dependencies") or []) if isinstance(x, dict)]
        result.append({"id": v.get("id"), "version_number": v.get("version_number"), "date_published": v.get("date_published"),
                       "game_versions": v.get("game_versions"), "loaders": v.get("loaders"), "version_type": v.get("version_type"),
                       "dependencies": deps, "files": files})
    return result


def _upd_slim_project(p):
    if not isinstance(p, dict):
        return p
    keys = ("id", "slug", "title", "project_type", "game_versions", "loaders")
    return {k: p.get(k) for k in keys if k in p}


def upd_fetch_target_versions(pid, mc, loader, fresh=False):
    gvs = [mc] + ([upd_parent_mc(mc)] if upd_parent_mc(mc) else [])
    key = f"uver2:{pid}:{loader}:{','.join(gvs)}"
    if fresh:
        CACHE.pop(key, None)
    url = (f"{MR_API}/project/{urllib.parse.quote(str(pid), safe='')}/version"
           f"?loaders={urllib.parse.quote(json.dumps([loader]), safe='')}&game_versions={urllib.parse.quote(json.dumps(gvs), safe='')}")
    data = cached_get_json(key, url, slim=_upd_slim_versions)
    if data is not None and not isinstance(data, list):
        CACHE.pop(key, None)
        return None
    return data


def upd_fetch_project(pid, fresh=False):
    key = f"proj2:{pid}"
    if fresh:
        CACHE.pop(key, None)
    return cached_get_json(key, f"{MR_API}/project/{urllib.parse.quote(str(pid), safe='')}", slim=_upd_slim_project)


def upd_cand_mr(v):
    files = [f for f in (v.get("files") or []) if isinstance(f, dict)]
    primary = next((f for f in files if f.get("primary")), (files[0] if files else None))
    hs = primary.get("hashes") if primary and isinstance(primary.get("hashes"), dict) else {}
    deps = []
    for d in v.get("dependencies") or []:
        if isinstance(d, dict) and isinstance(d.get("project_id"), str) and d.get("dependency_type") in ("required", "optional", "incompatible", "embedded"):
            deps.append({"pid": d["project_id"], "src": "modrinth", "type": d["dependency_type"]})
    ver = str(v.get("version_number") or "?")
    return {"id": v.get("id"), "version": ver,
            "type": v.get("version_type") if v.get("version_type") in UPD_CHANNELS else "release",
            "date": str(v.get("date_published") or ""),
            "filename": safe_jar_name(primary.get("filename") if primary else None, ver),
            "url": primary.get("url") if primary else None,
            "size": primary.get("size") if primary and isinstance(primary.get("size"), int) else None,
            "sha1": hs.get("sha1"), "sha512": hs.get("sha512"), "deps": deps,
            "tags": [g for g in (v.get("game_versions") or []) if isinstance(g, str)][:8]}


def upd_pool_mr(versions, mc, loader):
    pool = {"exact": {}, "near": {}}
    parent = upd_parent_mc(mc)
    for v in versions or []:
        if not isinstance(v, dict) or loader not in (v.get("loaders") or []):
            continue
        gv = v.get("game_versions") or []
        kind = "exact" if mc in gv else ("near" if parent and parent in gv else None)
        if not kind:
            continue
        cand = upd_cand_mr(v)
        cur = pool[kind].get(cand["type"])
        if cur is None or cand["date"] > cur["date"]:
            pool[kind][cand["type"]] = cand
    return pool


def upd_cf_file_sha1(row):
    for entry in row.get("hashes") or []:
        if isinstance(entry, dict) and entry.get("algo") == 1 and entry.get("value"):
            return str(entry["value"]).lower()
    return None


def upd_pool_cf(files, mc, loader):
    pool = {"exact": {}, "near": {}}
    parent = upd_parent_mc(mc)
    for f in files or []:
        if not isinstance(f, dict):
            continue
        tags = [str(x).lower() for x in (f.get("gameVersions") or [])]
        if loader not in tags:
            continue
        kind = "exact" if mc in tags else ("near" if parent and parent in tags else None)
        if not kind:
            continue
        ch = {1: "release", 2: "beta", 3: "alpha"}.get(f.get("releaseType"), "release")
        stem = os.path.splitext(str(f.get("fileName") or ""))[0]
        dep_rows = []
        for dep in f.get("dependencies") or []:
            if not isinstance(dep, dict) or not dep.get("modId"):
                continue
            dep_type = {3: "required", 2: "optional", 5: "incompatible", 1: "embedded", 6: "embedded", 4: "embedded"}.get(dep.get("relationType"), "embedded")
            if dep_type in ("required", "optional", "incompatible", "embedded"):
                dep_rows.append({"pid": str(dep["modId"]), "src": "curseforge", "type": dep_type})
        cand = {"id": str(f.get("id")) if f.get("id") is not None else None,
                "version": str(f.get("displayName") or stem or "?"), "type": ch,
                "date": str(f.get("fileDate") or ""), "filename": safe_jar_name(f.get("fileName"), "mod"),
                "url": f.get("downloadUrl"), "size": f.get("fileLength") if isinstance(f.get("fileLength"), int) else None,
                "sha1": upd_cf_file_sha1(f), "sha512": None, "deps": dep_rows,
                "tags": [t for t in tags if t[:1].isdigit()][:8]}
        cur = pool[kind].get(ch)
        if cur is None or cand["date"] > cur["date"]:
            pool[kind][ch] = cand
    return pool


def upd_allowed(plan):
    return UPD_CHANNELS[: UPD_CHANNELS.index(plan.get("channel", "release")) + 1]


def upd_newer(item, cand):
    if not item.get("ident") or not item.get("inst_date"):
        return False
    if versions_same(str(item.get("installed") or ""), str(cand.get("version") or "")):
        return False
    return bool(cand.get("date")) and cand["date"] > item["inst_date"]


def upd_resolve(item, plan):
    state = item.get("state")
    if state == "broken":
        return "broken", None, None
    if state == "error":
        return "error", None, None
    if state == "unknown":
        return ("current" if item.get("compat") else "unknown"), None, None
    pool = item.get("pool") or {}
    allowed = upd_allowed(plan)
    cand, kind = None, None
    if item.get("picked"):
        cand, kind = item["picked"], "picked"
    else:
        for k in ("exact", "near"):
            for ch in allowed:
                c = (pool.get(k) or {}).get(ch)
                if c:
                    cand, kind = c, k
                    break
            if cand:
                break
    if cand is not None:
        if kind == "near" and not plan.get("near"):
            return ("current" if item.get("compat") else "near"), cand, kind
        if item.get("compat") and kind != "picked" and not upd_newer(item, cand):
            return "current", cand, kind
        if not cand.get("url"):
            return "manual", cand, kind
        return "ready", cand, kind
    if item.get("compat"):
        return "current", None, None
    for ch in UPD_CHANNELS:
        if ch not in allowed:
            c = (pool.get("exact") or {}).get(ch)
            if c:
                return "beta", c, "exact"
    return "nofile", None, None


def upd_action(item, plan):
    status = upd_resolve(item, plan)[0]
    mark = item.get("action", "auto")
    if item.get("extra"):
        return "add" if status == "ready" and mark != "drop" else "none"
    if mark == "keep":
        return "keep"
    if mark == "drop":
        return "drop"
    if status == "ready":
        return "update"
    if status in ("current", "broken", "error") or item.get("compat") is True or item.get("compat") is None:
        return "keep"
    return "unported"


def upd_deps_of(m):
    data = m.get("data")
    modid = m.get("modid")
    if not isinstance(data, dict) or not isinstance(modid, str):
        return []
    table = data.get("dependencies")
    lst = table.get(modid) if isinstance(table, dict) else None
    return [d for d in lst if isinstance(d, dict)] if isinstance(lst, list) else []


def upd_compat_toml(m, mc, loader, path):
    try:
        with zipfile.ZipFile(path) as jar:
            name_map = _jar_name_map(jar.namelist())
    except (OSError, zipfile.BadZipFile, RuntimeError):
        return None
    data = m.get("data") if isinstance(m.get("data"), dict) else {}
    if loader == "fabric":
        if "fabric.mod.json" not in name_map:
            return False if ("quilt.mod.json" in name_map or "meta-inf/mods.toml" in name_map or "meta-inf/neoforge.mods.toml" in name_map) else None
    elif loader == "quilt":
        if "quilt.mod.json" not in name_map:
            return False
    elif loader == "forge":
        if "meta-inf/mods.toml" not in name_map:
            return False
    elif loader == "neoforge":
        if "meta-inf/neoforge.mods.toml" not in name_map:
            return False
    else:
        return None
    minecraft_range = None
    table = data.get("dependencies") if isinstance(data.get("dependencies"), dict) else {}
    mod_entries = data.get("mods") if isinstance(data.get("mods"), list) else []
    for entry in mod_entries:
        if not isinstance(entry, dict):
            continue
        modid = entry.get("modId")
        deps = table.get(modid, []) if modid else []
        for dep in deps if isinstance(deps, list) else []:
            if isinstance(dep, dict) and dep.get("modId") == "minecraft":
                value = dep.get("versionRange")
                if isinstance(value, str) and value.strip():
                    minecraft_range = value.strip()
                    break
        if minecraft_range:
            break
    if minecraft_range:
        return version_satisfies(mc, minecraft_range)
    return None


def upd_support_note(pid):
    p = upd_fetch_project(pid)
    if not isinstance(p, dict):
        return ""
    gv = sorted({g for g in (p.get("game_versions") or []) if isinstance(g, str)}, key=version_key)[-6:]
    ld = [g for g in (p.get("loaders") or []) if isinstance(g, str)]
    return upd_t("support_line", gv=", ".join(gv) or "?", ld=", ".join(ld) or "?")


def upd_blank_item(key, display):
    return {"key": key, "display": display, "modid": None, "sha256": None, "installed": None, "side": "unknown",
            "extra": False, "action": "auto", "picked": None, "state": "unknown", "compat": False, "compat_src": None,
            "ident": False, "inst_date": None, "src": None, "project": None, "page": None,
            "pool": {"exact": {}, "near": {}}, "note": "", "staged": None, "staged_sha256": None, "staged_modids": [],
            "stage_error": None, "required_by": []}


def upd_make_item(m, ident_row, last_m, plan, api_key, fresh, path):
    mc, loader = plan["target"]["mc"], plan["target"]["loader"]
    data = m.get("data")
    item = upd_blank_item(m["fname"], m.get("display") or m["fname"])
    item["modid"] = m.get("modid") or next(iter((m.get("artifact_meta") or {}).get("modids", [])), None)
    item["sha256"] = m.get("sha256")
    if isinstance(last_m, dict) and last_m.get("side_class") in ("client", "server", "both"):
        item["side"] = last_m["side_class"]
    ents = data.get("mods") if isinstance(data, dict) else None
    if m.get("error") or not isinstance(ents, list) or not ents or not isinstance(ents[0], dict):
        item["state"] = "broken"
        item["note"] = str(m.get("error") or "")
        return item
    ver = ents[0].get("version")
    item["installed"] = ver if isinstance(ver, str) else (str(ver) if ver is not None else None)
    if ident_row:
        item["ident"] = True
        item["inst_date"] = ident_row.get("date_published")
        item["compat"] = mc in ident_row.get("game_versions", []) and loader in ident_row.get("loaders", [])
        item["compat_src"] = "hash"
    else:
        item["compat"] = upd_compat_toml(m, mc, loader, path)
        item["compat_src"] = "toml"

    errors_before = NET_STATS["errors"]
    pid = ident_row["project_id"] if ident_row else None
    cf_id = last_m.get("cf_id") if isinstance(last_m, dict) else None
    cf_slug = last_m.get("cf_slug") if isinstance(last_m, dict) else None
    if not pid and isinstance(last_m, dict) and last_m.get("modrinth_id"):
        pid = str(last_m["modrinth_id"])
    if pid:
        try:
            matched_mr, matched_cf = _FINDER_FIND_MAIN_MOD_BASE("https://modrinth.com/mod/" + str(pid), api_key)
            if matched_cf:
                cf_id, cf_slug = matched_cf.get("id") or cf_id, matched_cf.get("slug") or cf_slug
        except Exception:
            pass
    if not pid and isinstance(m.get("artifact_meta"), dict):
        for metadata_url in m["artifact_meta"].get("links") or []:
            try:
                matched_mr, matched_cf = _FINDER_FIND_MAIN_MOD_BASE(metadata_url, api_key)
            except Exception:
                matched_mr, matched_cf = None, None
            if matched_mr or matched_cf:
                if matched_mr:
                    pid = matched_mr.get("id") or matched_mr.get("slug")
                if matched_cf:
                    cf_id, cf_slug = matched_cf.get("id") or cf_id, matched_cf.get("slug") or cf_slug
                break
    if not pid and item["modid"]:
        mr = fetch_modrinth(item["modid"]) or search_modrinth(item["display"], item["modid"])
        if isinstance(mr, dict):
            pid = mr.get("project_id") or mr.get("id") or mr.get("slug")
    if pid:
        item["src"] = "modrinth"
        item["project"] = {"id": str(pid), "src": "modrinth", "mr_id": str(pid),
                           "cf_id": str(cf_id) if cf_id else None, "cf_slug": cf_slug}
        item["page"] = f"https://modrinth.com/project/{pid}"
        versions = upd_fetch_target_versions(pid, mc, loader, fresh)
        if versions is None:
            item["state"] = "error"
        else:
            item["pool"] = upd_pool_mr(versions, mc, loader)
            item["state"] = "resolved"

    have = bool(item["pool"]["exact"] or item["pool"]["near"])
    if not have and item["state"] != "error" and _cf_ready(api_key):
        if not cf_id:
            src = (fetch_curseforge_by_slug(item["modid"], api_key) if item["modid"] else None) or search_curseforge(item["display"], api_key, item["modid"])
            if isinstance(src, dict):
                cf_id, cf_slug = src.get("id"), src.get("slug")
        if cf_id:
            files = fetch_curseforge_files(cf_id, api_key)
            if files is not None:
                pool = upd_pool_cf(files, mc, loader)
                if pool["exact"] or pool["near"] or not pid:
                    item["pool"] = pool
                    item["src"] = "curseforge"
                    item["project"] = {"id": str(cf_id), "src": "curseforge", "cf_id": str(cf_id),
                                       "cf_slug": cf_slug, "mr_id": str(pid) if pid else None}
                    item["page"] = f"https://www.curseforge.com/minecraft/mc-mods/{cf_slug}" if cf_slug else None
                    item["state"] = "resolved"
            elif not pid:
                item["state"] = "error"
    if item["state"] == "unknown" and NET_STATS["errors"] > errors_before:
        item["state"] = "error"
    if item["state"] == "resolved" and not item["compat"] and not (item["pool"]["exact"] or item["pool"]["near"]) and item["src"] == "modrinth":
        item["note"] = upd_support_note(item["project"]["id"])
    return item


def upd_project_keys(item):
    project = item.get("project") if isinstance(item.get("project"), dict) else {}
    keys = set()
    if project.get("mr_id"):
        keys.add(("modrinth", str(project["mr_id"])))
    if project.get("cf_id"):
        keys.add(("curseforge", str(project["cf_id"])))
    if project.get("id"):
        source = str(project.get("src") or item.get("src") or "modrinth").lower()
        source = "curseforge" if source in ("cf", "curseforge") else "modrinth"
        keys.add((source, str(project["id"])))
    return keys


def upd_dep_key(dep):
    source = str(dep.get("src") or "modrinth").lower()
    source = "curseforge" if source in ("cf", "curseforge") else "modrinth"
    pid = dep.get("pid")
    return (source, str(pid)) if pid is not None and str(pid) else None


def upd_make_extra(dep, by, plan, fresh, api_key=None):
    mc, loader = plan["target"]["mc"], plan["target"]["loader"]
    source, pid = upd_dep_key(dep) or ("modrinth", str(dep))
    title = str(pid)
    item = upd_blank_item(("+mr:" if source == "modrinth" else "+cf:") + str(pid), title)
    item["extra"] = True
    item["required_by"] = list(by)

    if source == "curseforge" and not api_key:
        item["src"] = "curseforge"
        item["project"] = {"id": str(pid), "src": "curseforge", "mr_id": None,
                           "cf_id": str(pid), "cf_slug": None}
        item["state"] = "unknown"
        item["note"] = upd_t("extra_cf_key")
        return item

    mr_id = str(pid) if source == "modrinth" else None
    cf_id = str(pid) if source == "curseforge" else None
    cf_slug = None
    mr_card = None

    if source == "curseforge":
        raw = None
        try:
            raw = _AUTO_FINDER["cf_mod_by_id"](pid, api_key)
        except Exception:
            raw = None
        slim = _AUTO_FINDER["slim_cf_hit"](raw) if isinstance(raw, dict) else None
        if isinstance(slim, dict):
            title = str(slim.get("name") or title)
            item["display"] = title
            cf_slug = slim.get("slug")
        if cf_slug:
            try:
                mr_card, _cf_pair = _FINDER_FIND_MAIN_MOD_BASE(
                    "https://www.curseforge.com/minecraft/mc-mods/" + str(cf_slug), api_key)
            except Exception:
                mr_card = None
        if mr_card:
            mr_id = mr_card.get("id") or mr_card.get("slug")
    else:
        proj = upd_fetch_project(pid, fresh)
        if isinstance(proj, dict) and isinstance(proj.get("title"), str):
            title = proj["title"]
            item["display"] = title
        try:
            _mr_card, cf_slim = _FINDER_FIND_MAIN_MOD_BASE(
                "https://modrinth.com/mod/" + str(pid), api_key)
            if cf_slim:
                cf_id = str(cf_slim.get("id")) if cf_slim.get("id") else None
                cf_slug = cf_slim.get("slug")
        except Exception:
            pass

    mr_pool = {"exact": {}, "near": {}}
    mr_versions_ok = False
    if mr_id:
        versions = upd_fetch_target_versions(mr_id, mc, loader, fresh)
        if versions is not None:
            mr_versions_ok = True
            mr_pool = upd_pool_mr(versions, mc, loader)

    if mr_pool["exact"] or mr_pool["near"]:
        item["src"] = "modrinth"
        item["project"] = {"id": str(mr_id), "src": "modrinth", "mr_id": str(mr_id),
                           "cf_id": str(cf_id) if cf_id else None, "cf_slug": cf_slug}
        item["page"] = f"https://modrinth.com/project/{mr_id}"
        item["pool"] = mr_pool
        item["state"] = "resolved"
        return item

    cf_pool = {"exact": {}, "near": {}}
    cf_files_ok = False
    if api_key and cf_id:
        files = fetch_curseforge_files(cf_id, api_key)
        if files is not None:
            cf_files_ok = True
            cf_pool = upd_pool_cf(files, mc, loader)

    if cf_pool["exact"] or cf_pool["near"]:
        item["src"] = "curseforge"
        item["project"] = {"id": str(cf_id), "src": "curseforge", "mr_id": str(mr_id) if mr_id else None,
                           "cf_id": str(cf_id), "cf_slug": cf_slug}
        item["page"] = (f"https://www.curseforge.com/minecraft/mc-mods/{cf_slug}" if cf_slug else None)
        item["pool"] = cf_pool
        item["state"] = "resolved"
        return item

    if mr_id:
        item["src"] = "modrinth"
        item["project"] = {"id": str(mr_id), "src": "modrinth", "mr_id": str(mr_id),
                           "cf_id": str(cf_id) if cf_id else None, "cf_slug": cf_slug}
        item["page"] = f"https://modrinth.com/project/{mr_id}"
        item["pool"] = mr_pool
        item["state"] = "resolved" if mr_versions_ok else "error"
        if mr_versions_ok:
            item["note"] = upd_support_note(mr_id)
        return item

    item["src"] = "curseforge"
    item["project"] = {"id": str(cf_id), "src": "curseforge", "mr_id": None,
                       "cf_id": str(cf_id), "cf_slug": cf_slug}
    item["page"] = (f"https://www.curseforge.com/minecraft/mc-mods/{cf_slug}" if cf_slug else None)
    item["pool"] = cf_pool
    item["state"] = "resolved" if cf_files_ok else "error"
    return item


def upd_compute_extras(plan, fresh=False, api_key=None):
    old = {}
    for it in plan["items"]:
        if it.get("extra"):
            for project_key in upd_project_keys(it):
                old[project_key] = it
    base = [it for it in plan["items"] if not it.get("extra")]
    known = {}
    for it in base:
        for project_key in upd_project_keys(it):
            known[project_key] = it
    extras = {}
    sources = base
    for _round in range(8):
        fresh_extras = []
        for it in sources:
            if upd_action(it, plan) not in ("update", "add"):
                continue
            cand = upd_resolve(it, plan)[1]
            for dep in (cand or {}).get("deps", []):
                if dep.get("type") != "required":
                    continue
                dep_key = upd_dep_key(dep)
                if not dep_key or dep_key in known:
                    continue
                if dep_key in extras:
                    if it["display"] not in extras[dep_key]["required_by"]:
                        extras[dep_key]["required_by"].append(it["display"])
                    continue
                prev = old.get(dep_key)
                if prev is not None:
                    prev["required_by"] = [it["display"]]
                    extra = prev
                else:
                    extra = upd_make_extra(dep, [it["display"]], plan, fresh, api_key or _UPD_API_KEY)
                extras[dep_key] = extra
                for alias in upd_project_keys(extra):
                    known[alias] = extra
                fresh_extras.append(extra)
        if not fresh_extras:
            break
        sources = fresh_extras
    plan["items"] = base + sorted({id(x): x for x in extras.values()}.values(), key=lambda x: x["display"].lower())


def upd_dep_problems(item, plan):
    cand = upd_resolve(item, plan)[1]
    if upd_action(item, plan) not in ("update", "add") or not cand:
        return []
    by_project = {}
    for it in plan["items"]:
        for key in upd_project_keys(it):
            by_project[key] = it
    issues = []
    for dep in cand.get("deps", []):
        if dep.get("type") not in ("required", "incompatible"):
            continue
        key = upd_dep_key(dep)
        other = by_project.get(key) if key else None
        if dep.get("type") == "required":
            if other is None:
                issues.append(str(dep.get("pid")) + " (not resolved)")
            elif other is not item and upd_action(other, plan) not in (("add",) if other.get("extra") else ("update", "keep")):
                issues.append(other["display"])
        elif other is not None and other is not item and upd_action(other, plan) in ("update", "keep", "add"):
            issues.append(other["display"] + " (incompatible)")
    return list(dict.fromkeys(issues))


def upd_refresh_extras(plan):
    try:
        upd_compute_extras(plan, api_key=_UPD_API_KEY)
    except (OSError, ValueError, TypeError, KeyError, AttributeError):
        pass
    upd_save()


def upd_counts(plan):
    c = {}
    for it in plan["items"]:
        key = "extras" if it.get("extra") else upd_resolve(it, plan)[0]
        c[key] = c.get(key, 0) + 1
    c["blockers"] = sum(1 for it in plan["items"] if it.get("extra") and upd_resolve(it, plan)[0] != "ready")
    c["depgap"] = sum(1 for it in plan["items"] if upd_dep_problems(it, plan))
    return c


def upd_print_summary(plan):
    mc, loader = plan["target"]["mc"], plan["target"]["loader"]
    c = upd_counts(plan)
    say(f"{GREEN}{BOLD}{upd_t('sum_title', mc=mc, loader=loader, ch='/'.join(upd_allowed(plan)))}{RESET}")
    parent = upd_parent_mc(mc) or mc
    for key, color in (("ready", GREEN), ("current", DIM), ("near", YELLOW), ("beta", YELLOW), ("manual", YELLOW),
                       ("nofile", RED), ("unknown", RED), ("error", YELLOW), ("broken", RED)):
        if c.get(key):
            say(f"{color}{upd_t('sum_' + key, n=c[key], parent=parent)}{RESET}")
    if c.get("extras"):
        say(upd_t("sum_extras", n=c["extras"]))
        if c.get("blockers"):
            say(f"{RED}{upd_t('sum_blockers', n=c['blockers'])}{RESET}")
    if c.get("depgap"):
        say(f"{RED}{upd_t('sum_depgap', n=c['depgap'])}{RESET}")
    if plan.get("stale"):
        say(f"{YELLOW}{upd_t('stale')}{RESET}")


def upd_detect_source(ident):
    counts = {}
    for row in ident.values():
        for gv in row.get("game_versions", []):
            for ld in row.get("loaders", []):
                counts[(gv, ld)] = counts.get((gv, ld), 0) + 1
    if len(ident) < 3 or not counts:
        return None
    (gv, ld), n = max(counts.items(), key=lambda kv: (kv[1], version_key(kv[0][0])))
    return {"mc": gv, "loader": ld, "n": n}


# c166
def upd_build(plan, api_key, fresh=False):
    mc, loader = plan["target"]["mc"], plan["target"]["loader"]
    if not check_internet():
        say(f"{RED}{upd_t('offline')}{RESET}")
        return False
    mods, local_modids, _disp, _files, _disabled, _ident = scan_mods()
    if not mods:
        say(upd_t("plan_empty"))
        return False
    previous = {m.get("fname"): m for m in (LAST_RUN or {}).get("mods", []) if isinstance(m, dict)}
    for mod in mods:
        old_mod = previous.get(mod.get("fname"))
        if old_mod and old_mod.get("sha256") == mod.get("sha256") and old_mod.get("was_manual"):
            mod["side_class"] = old_mod.get("side_class", "unknown")
            mod["client_side"] = old_mod.get("client_side")
            mod["server_side"] = old_mod.get("server_side")
            mod["was_manual"] = True
        if mod.get("error"):
            init_side_fields(mod)
            try:
                _finder_resolve_local_mod(mod, True, api_key)
            except Exception:
                pass
        else:
            try:
                classify_mod(mod, True, api_key)
            except Exception:
                init_side_fields(mod)
    last = {m.get("fname"): m for m in mods if isinstance(m, dict)}
    old_items = {it["key"]: it for it in plan["items"] if not it.get("extra")}
    same_target = plan.get("planned_target") == [mc, loader]
    say(upd_t("plan_start", n=len(mods), mc=mc, loader=loader))
    paths = {m["fname"]: os.path.join(SCRIPT_DIR, m["fname"]) for m in mods if not m.get("error")}
    say(upd_t("plan_hash"))
    ident = upd_identify(paths)
    say(upd_t("plan_ident", found=len(ident), n=len(paths)))
    plan["source"] = upd_detect_source(ident)
    if plan["source"]:
        say(upd_t("plan_source", mc=plan["source"]["mc"], loader=plan["source"]["loader"], n=plan["source"]["n"], tmc=mc, tloader=loader))
        if plan["source"]["loader"] != loader:
            say(f"{YELLOW}{upd_t('plan_loader_change', a=plan['source']['loader'], b=loader)}{RESET}")
    new_items = []
    for i, m in enumerate(mods, 1):
        item = upd_make_item(m, ident.get(m["fname"]), last.get(m["fname"]), plan, api_key, fresh, paths.get(m["fname"]))
        prev = old_items.get(item["key"])
        if prev and prev.get("sha256") == item.get("sha256"):
            item["action"] = prev.get("action", "auto")
            if same_target:
                item["picked"] = prev.get("picked")
        new_items.append(item)
        if i % 10 == 0 or i == len(mods):
            say(upd_t("plan_progress", i=i, n=len(mods)))
    new_items.sort(key=lambda it: (it.get("display") or "").lower())
    plan["items"] = new_items
    say(upd_t("plan_extras"))
    upd_compute_extras(plan, fresh, api_key)
    plan["planned"] = upd_now()
    plan["planned_target"] = [mc, loader]
    plan["stale"] = False
    plan["local_modids"] = sorted(local_modids)
    save_cache()
    upd_save()
    upd_print_summary(plan)
    say(upd_t("sum_next"))
    return True


def upd_find_items(plan, tokens):
    items = plan["items"]
    found, errors = [], []

    def add(it):
        if it not in found:
            found.append(it)

    def by_name(q):
        q = q.lower()
        hits = [it for it in items if (it.get("modid") or "").lower() == q or (it.get("display") or "").lower() == q
                or it["key"].lower() in (q, q + ".jar")]
        if not hits:
            hits = [it for it in items if q in (it.get("display") or "").lower() or q in it["key"].lower()]
        return hits

    words = [t for t in tokens if not re.fullmatch(r"\d+(-\d+)?", t)]
    if len(tokens) > 1 and len(words) == len(tokens):
        hits = by_name(" ".join(tokens))
        if len(hits) == 1:
            return hits, errors
    for tok in tokens:
        m = re.fullmatch(r"(\d+)(?:-(\d+))?", tok)
        if m:
            a = int(m.group(1))
            b = int(m.group(2)) if m.group(2) else a
            for n in range(a, b + 1):
                if 1 <= n <= len(items):
                    add(items[n - 1])
                else:
                    errors.append(upd_t("bad_number", v=n))
            continue
        hits = by_name(tok)
        if len(hits) == 1:
            add(hits[0])
        elif not hits:
            errors.append(upd_t("no_item", v=tok))
        else:
            errors.append(upd_t("ambiguous", v=tok, names=", ".join(upd_cut(h["display"], 24) for h in hits[:6])))
    return found, errors


def upd_index(plan, item):
    return plan["items"].index(item) + 1


def upd_line(n, item, plan):
    status, cand, kind = upd_resolve(item, plan)
    mark, color = UPD_MARK[status]
    name = upd_cut(item.get("display") or item["key"], 30).ljust(30)
    inst = upd_cut(item.get("installed") or "?", 14)
    if item.get("extra"):
        tail = (f"-> {upd_cut(cand['version'], 18)}" if cand else upd_t("st_" + status)) + "  " + DIM + upd_t("tag_extra", by=", ".join(item["required_by"][:3])) + RESET
    elif cand and status in ("ready", "near", "beta", "manual"):
        info = []
        if cand.get("type") and cand["type"] != "release":
            info.append(cand["type"])
        if kind == "near":
            info.append("~")
        src = "CF" if item.get("src") == "curseforge" else "MR"
        tail = f"{inst:<14} -> {upd_cut(cand['version'], 22)}  {DIM}{' '.join(info + [src])}{RESET}"
    else:
        tail = f"{inst:<14}  {DIM}{upd_t('st_' + status)}{RESET}"
    tags = ""
    if item.get("action") == "keep":
        tags += " " + YELLOW + upd_t("tag_keep") + RESET
    elif item.get("action") == "drop":
        tags += " " + YELLOW + upd_t("tag_drop") + RESET
    if item.get("picked"):
        tags += " " + YELLOW + upd_t("tag_picked") + RESET
    if item.get("staged"):
        tags += " " + GREEN + upd_t("tag_staged") + RESET
    if upd_dep_problems(item, plan):
        tags += " " + RED + upd_t("tag_depgap") + RESET
    return f"{n:>3}. {color}[{mark}]{RESET} {name} {tail}{tags}"


def upd_group(item, plan):
    if item.get("extra"):
        return "extras"
    status = upd_resolve(item, plan)[0]
    if status in UPD_PROBLEMS:
        return "problems"
    return "ready" if status == "ready" else "current"


def upd_cmd_list(args, plan):
    flt = args[0].lower() if args else ""
    statuses = ("ready", "current", "nofile", "unknown", "manual", "beta", "near", "error", "broken")
    if flt and flt not in ("all", "problems", "problem", "extra", "extras", "keep", "drop", "unported") and flt not in statuses:
        say(upd_t("list_filter_bad", v=flt))
        return
    if plan.get("stale"):
        say(f"{YELLOW}{upd_t('stale')}{RESET}")
    numbered = list(enumerate(plan["items"], 1))
    if flt in statuses:
        rows = [(n, it) for n, it in numbered if upd_resolve(it, plan)[0] == flt and not it.get("extra")]
        grouped = {"rows": rows}
    elif flt in ("keep", "drop", "unported"):
        rows = [(n, it) for n, it in numbered if upd_action(it, plan) == flt]
        grouped = {"rows": rows}
    elif flt in ("extra", "extras"):
        grouped = {"rows": [(n, it) for n, it in numbered if it.get("extra")]}
    elif flt in ("problems", "problem"):
        grouped = {"rows": [(n, it) for n, it in numbered if upd_group(it, plan) in ("problems",)]}
    else:
        grouped = {g: [(n, it) for n, it in numbered if upd_group(it, plan) == g] for g in ("problems", "ready", "current", "extras")}
    if "rows" in grouped:
        if not grouped["rows"]:
            say(upd_t("list_empty"))
        for n, it in grouped["rows"]:
            say(upd_line(n, it, plan))
        return
    for g, title in (("problems", "grp_problems"), ("ready", "grp_ready"), ("extras", "grp_extras"), ("current", "grp_current")):
        rows = grouped[g]
        if not rows:
            continue
        if g == "current" and flt != "all":
            say(DIM + upd_t("current_collapsed", n=len(rows)) + RESET)
            continue
        say(f"{BOLD}{upd_t(title)}{RESET}")
        for n, it in rows:
            say(upd_line(n, it, plan))


def upd_action_text(act):
    return upd_t("act_" + act)


def upd_cmd_show(args, plan):
    items, errors = upd_find_items(plan, args)
    for e in errors:
        say(f"{YELLOW}{e}{RESET}")
    if not args:
        say(upd_t("need_items", cmd="show"))
        return
    for item in items[:3]:
        n = upd_index(plan, item)
        status, cand, kind = upd_resolve(item, plan)
        say(f"{GREEN}{BOLD}{upd_t('show_title', n=n, name=item['display'])}{RESET}")
        if not item.get("extra"):
            say(upd_t("show_file", f=item["key"]))
            side = item.get("side") if item.get("side") not in (None, "unknown") else "?"
            say(upd_t("show_modid", m=item.get("modid") or "?", v=item.get("installed") or "?", s=side))
            src = {"hash": upd_t("src_hash"), "toml": upd_t("src_toml")}.get(item.get("compat_src"), "?")
            say(upd_t("show_compat_yes" if item.get("compat") else "show_compat_no", src=src))
        else:
            say(upd_t("show_required_by", by=", ".join(item["required_by"])))
        say(upd_t("show_src", src=item.get("src") or "-", page=item.get("page") or "-"))
        mark, color = UPD_MARK[status]
        say(upd_t("show_status", st=f"{color}[{mark}] {upd_t('st_' + status)}{RESET}"))
        if item.get("note"):
            say(upd_t("show_support" if status == "nofile" else "show_note", s=item["note"], note=item["note"]))
        pool = item.get("pool") or {}
        rows = [(k, pool[k][ch]) for k in ("exact", "near") for ch in UPD_CHANNELS if pool.get(k, {}).get(ch)]
        if rows:
            say(upd_t("show_cands"))
            for k, c in rows:
                say(upd_t("show_cand_line", kind=upd_t("kind_" + k), typ=c["type"], ver=c["version"], date=(c.get("date") or "")[:10]))
        if cand:
            size = ""
            if isinstance(cand.get("size"), int):
                size = f", {round(cand['size'] / 1024)} KB" if cand["size"] >= 1024 else f", {cand['size']} B"
            say(upd_t("show_chosen", ver=cand["version"], typ=cand["type"], extra="", fn=cand["filename"], size=size))
            req = [d for d in cand.get("deps", []) if d.get("type") == "required"]
            if req:
                say(upd_t("show_deps", n=len(req)))
        gap = upd_dep_problems(item, plan)
        if gap:
            say(f"{RED}{upd_t('show_depgap', names=', '.join(gap))}{RESET}")
        act = upd_action(item, plan)
        say(upd_t("show_action", act=upd_action_text(act)))
        if item.get("staged"):
            say(upd_t("show_staged", f=item["staged"]))
        if item.get("stage_error"):
            say(f"{RED}{upd_t('show_stage_err', e=item['stage_error'])}{RESET}")
        say(SEP_LINE)


def upd_cmd_mark(cmd, args, plan):
    if cmd == "reset" and args and args[0].lower() == "all":
        for it in plan["items"]:
            it["action"] = "auto"
            it["picked"] = None
        upd_refresh_extras(plan)
        say(upd_t("reset_all_done"))
        return
    if not args:
        say(upd_t("need_items", cmd=cmd))
        return
    items, errors = upd_find_items(plan, args)
    for e in errors:
        say(f"{YELLOW}{e}{RESET}")
    for it in items:
        if cmd == "reset":
            it["action"], it["picked"] = "auto", None
        else:
            it["action"] = cmd
    if items:
        upd_refresh_extras(plan)
        say(upd_t("mark_done", cmd=cmd, n=len(items)))


def upd_cmd_pick(args, plan):
    items, errors = upd_find_items(plan, args)
    for e in errors:
        say(f"{YELLOW}{e}{RESET}")
    if not items:
        if not args:
            say(upd_t("need_items", cmd="pick"))
        return
    item = items[0]
    pool = item.get("pool") or {}
    options = [(k, pool[k][ch]) for k in ("exact", "near") for ch in UPD_CHANNELS if pool.get(k, {}).get(ch)]
    if not options:
        say(upd_t("pick_none", name=item["display"]))
        return
    say(upd_t("pick_title", name=item["display"]))
    for i, (k, c) in enumerate(options, 1):
        say(upd_t("pick_line", i=i, typ=c["type"], ver=c["version"], date=(c.get("date") or "")[:10], kind=upd_t("kind_" + k)))
    answer = upd_ask(upd_t("pick_prompt"))
    if not answer.isdigit() or not 1 <= int(answer) <= len(options):
        say(T[LANG]["cancelled"])
        return
    item["picked"] = options[int(answer) - 1][1]
    item["action"] = "auto"
    item["stage_error"] = None
    upd_refresh_extras(plan)
    say(upd_t("pick_done", name=item["display"], ver=item["picked"]["version"]))


def upd_valid_mc(v):
    return bool(re.fullmatch(r"\d+\.\d+(\.\d+)?", str(v)))


def upd_set_target(mc, loader):
    global UPD, TARGET_MC, API_LOADER
    if not upd_valid_mc(mc):
        say(f"{RED}{upd_t('bad_mc', v=mc)}{RESET}")
        return False
    if loader not in UPD_LOADERS:
        say(f"{RED}{upd_t('bad_loader', v=loader, ok=', '.join(UPD_LOADERS))}{RESET}")
        return False
    plan = upd_load()
    if plan is None:
        UPD = upd_new_plan(mc, loader)
    elif plan["target"] != {"mc": mc, "loader": loader}:
        plan["target"] = {"mc": mc, "loader": loader}
        if plan["items"]:
            plan["stale"] = True
            say(f"{YELLOW}{upd_t('target_stale')}{RESET}")
    TARGET_MC, API_LOADER = mc, loader
    upd_save()
    return True


def upd_cmd_target(args):
    plan = upd_load()
    if not args:
        mc = plan["target"]["mc"] if plan else TARGET_MC
        loader = plan["target"]["loader"] if plan else API_LOADER
        say(upd_t("target_now", mc=mc, loader=loader) if mc else upd_t("target_none"))
        return
    loader = args[1].lower() if len(args) > 1 else (plan["target"]["loader"] if plan else API_LOADER)
    if upd_set_target(args[0], loader):
        say(upd_t("target_set", mc=args[0], loader=loader))


def upd_cmd_channel(args, plan):
    if args:
        if args[0].lower() not in UPD_CHANNELS:
            say(upd_t("channel_bad"))
            return
        plan["channel"] = args[0].lower()
        upd_refresh_extras(plan)
    say(upd_t("channel_now", ch="/".join(upd_allowed(plan)), desc=upd_t("channel_desc_" + plan["channel"])))


def upd_cmd_near(args, plan):
    mc = plan["target"]["mc"]
    parent = upd_parent_mc(mc)
    if args:
        if args[0].lower() not in ("on", "off"):
            say(upd_t("near_bad"))
            return
        plan["near"] = args[0].lower() == "on"
        upd_refresh_extras(plan)
    if not parent:
        say(upd_t("near_no_parent", mc=mc))
    else:
        say(upd_t("near_on", parent=parent) if plan["near"] else upd_t("near_off", mc=mc))


def upd_rm(path):
    try:
        os.remove(path)
    except OSError:
        pass


def upd_hash_ok(path, cand):
    want = cand.get("sha512") or cand.get("sha1")
    if not want:
        return None
    try:
        return upd_hash_file(path, "sha512" if cand.get("sha512") else "sha1") == str(want).lower()
    except OSError:
        return False


def upd_is_staged(item, plan):
    name = item.get("staged")
    if not name:
        return False
    path = os.path.join(upd_stage_dir(plan), name)
    try:
        return os.path.isfile(path) and file_sha256(path) == item.get("staged_sha256")
    except OSError:
        return False


def upd_stage_one(item, cand, plan, sdir, local_ids, used):
    fname = safe_jar_name(cand.get("filename"), item["key"])
    marker = str(cand.get("id") or cand.get("version"))
    if item.get("staged") == fname and item.get("staged_for") == marker and upd_is_staged(item, plan):
        return "had", ""
    if item.get("staged"):
        upd_rm(os.path.join(sdir, item["staged"]))
        item["staged"], item["staged_sha256"] = None, None
    if fname in used:
        fname = f"{upd_index(plan, item)}_{fname}"
    dest = os.path.join(sdir, fname)
    try:
        download_file(cand["url"], dest, expect_modid=None if item.get("extra") else item.get("modid"))
    except (OSError, urllib.error.URLError) as e:
        return "fail", str(e)
    if upd_hash_ok(dest, cand) is False:
        upd_rm(dest)
        return "fail", upd_t("stage_hash_bad")
    ids = jar_modids(dest)
    if item.get("extra") and ids & local_ids:
        upd_rm(dest)
        return "fail", upd_t("stage_dup", ids=", ".join(sorted(ids & local_ids)))
    item["staged"], item["staged_for"] = fname, marker
    item["staged_sha256"], item["staged_modids"] = file_sha256(dest), sorted(ids)
    return "ok", ""


def upd_cmd_stage(plan):
    todo = [it for it in plan["items"] if upd_action(it, plan) in ("update", "add")]
    if not todo:
        say(upd_t("stage_nothing"))
        return 0
    sdir = upd_stage_dir(plan)
    os.makedirs(sdir, exist_ok=True)
    local_ids = set(plan.get("local_modids", []))
    total = sum(upd_resolve(it, plan)[1].get("size") or 0 for it in todo)
    size_text = f", ~{total / 1048576:.1f} {upd_t('unit_mb')}" if total else ""
    say(upd_t("stage_start", dir=os.path.relpath(sdir, SCRIPT_DIR), n=len(todo), size=size_text))
    ok = had = bad = 0
    try:
        for it in todo:
            cand = upd_resolve(it, plan)[1]
            used = {o["staged"] for o in plan["items"] if o is not it and o.get("staged")}
            res, err = upd_stage_one(it, cand, plan, sdir, local_ids, used)
            if res == "ok":
                ok += 1
                it["stage_error"] = None
                say(upd_t("stage_ok", name=upd_cut(it["display"], 30), fn=it["staged"]))
            elif res == "had":
                had += 1
            else:
                bad += 1
                it["stage_error"] = err
                say(f"{RED}{upd_t('stage_fail', name=upd_cut(it['display'], 30), e=err)}{RESET}")
    finally:
        upd_save()
    say(upd_t("stage_done", ok=ok, had=had, bad=bad))
    if ok or had:
        say(upd_t("stage_next"))
    return bad


def upd_write_json(path, data):
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=1)
    os.replace(tmp, path)


def upd_old_unchanged(item):
    path = os.path.join(SCRIPT_DIR, item["key"])
    try:
        return os.path.isfile(path) and (not item.get("sha256") or file_sha256(path) == item["sha256"])
    except OSError:
        return False


def upd_names_line(items, limit=40):
    names = [upd_cut(it["display"], 28) for it in items[:limit]]
    more = f" (+{len(items) - limit})" if len(items) > limit else ""
    return upd_t("apply_names", names=", ".join(names) + more)


# c167
def upd_cmd_apply(args, plan):
    if plan.get("stale"):
        say(f"{YELLOW}{upd_t('stale')}{RESET}")
        return
    keep_unported = any(a.lower() in ("keep-unported", "keepall") for a in args)
    act = {it["key"]: upd_action(it, plan) for it in plan["items"]}
    ups = [it for it in plan["items"] if act[it["key"]] == "update"]
    adds = [it for it in plan["items"] if act[it["key"]] == "add"]
    drops = [it for it in plan["items"] if act[it["key"]] == "drop"]
    unported = [it for it in plan["items"] if act[it["key"]] == "unported"]
    kept = [it for it in plan["items"] if not it.get("extra") and (act[it["key"]] == "keep" or (keep_unported and act[it["key"]] == "unported"))]
    if keep_unported:
        unported = []
    if not (ups or adds or drops or unported):
        say(upd_t("apply_nothing"))
        return
    need = [it for it in ups + adds if not upd_is_staged(it, plan)]
    if need and upd_confirm(upd_t("apply_not_staged", n=len(need))):
        upd_cmd_stage(plan)
    left = [it for it in ups + adds if not upd_is_staged(it, plan)]
    ups = [it for it in ups if it not in left]
    adds = [it for it in adds if it not in left]
    if not (ups or adds or drops or unported):
        say(upd_t("apply_nothing"))
        return
    say(f"{GREEN}{BOLD}{upd_t('apply_title')}{RESET}")
    for key, items in (("apply_update", ups), ("apply_add", adds), ("apply_drop", drops), ("apply_unported", unported),
                       ("apply_unstaged", left), ("apply_keep", kept)):
        if items:
            say(upd_t(key, n=len(items)))
            if key in ("apply_drop", "apply_unported", "apply_unstaged"):
                say(f"{YELLOW}{upd_names_line(items)}{RESET}")
    gaps = [(it, upd_dep_problems(it, plan)) for it in ups + adds]
    gaps = [(it, g) for it, g in gaps if g]
    if gaps:
        say(f"{RED}{BOLD}{upd_t('apply_depgap_title')}{RESET}")
        for it, g in gaps:
            say(f"{RED}{upd_t('apply_depgap_line', name=upd_cut(it['display'], 28), deps=', '.join(g))}{RESET}")
    mc, loader = plan["target"]["mc"], plan["target"]["loader"]
    stamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    bdir = os.path.join(UPDATE_BACKUP_DIR, f"{stamp}_{mc}_{loader}")
    n = 1
    while os.path.exists(bdir):
        n += 1
        bdir = os.path.join(UPDATE_BACKUP_DIR, f"{stamp}_{mc}_{loader}_{n}")
    if not upd_confirm(upd_t("apply_confirm", dir=os.path.relpath(bdir, SCRIPT_DIR))):
        say(upd_t("apply_cancel"))
        return
    old_dir = os.path.join(bdir, "old")
    os.makedirs(old_dir, exist_ok=True)
    manifest = {"stamp": os.path.basename(bdir), "created": upd_now(), "target": plan["target"], "complete": False,
                "rolled_back": False, "entries": []}
    manifest_path = os.path.join(bdir, "manifest.json")
    upd_write_json(manifest_path, manifest)
    sdir = upd_stage_dir(plan)
    done = {"u": 0, "a": 0, "d": 0, "e": 0}

    def record(entry):
        manifest["entries"].append(entry)
        upd_write_json(manifest_path, manifest)

    def move_old(item):
        shutil.move(os.path.join(SCRIPT_DIR, item["key"]), os.path.join(old_dir, item["key"]))

    for it in ups + drops + unported:
        name = upd_cut(it["display"], 30)
        if not upd_old_unchanged(it):
            say(f"{YELLOW}{upd_t('apply_changed', name=name)}{RESET}")
            done["e"] += 1
            continue
        replacing = it in ups
        new_name = it.get("staged") if replacing else None
        if replacing:
            if not upd_is_staged(it, plan):
                say(f"{YELLOW}{upd_t('apply_skipped_unstaged', name=name)}{RESET}")
                done["e"] += 1
                continue
            dest = os.path.join(SCRIPT_DIR, new_name)
            if os.path.exists(dest) and os.path.abspath(dest) != os.path.abspath(os.path.join(SCRIPT_DIR, it["key"])):
                say(f"{YELLOW}{upd_t('apply_conflict', name=name, fn=new_name)}{RESET}")
                done["e"] += 1
                continue
        try:
            move_old(it)
            if replacing:
                try:
                    os.replace(os.path.join(sdir, new_name), os.path.join(SCRIPT_DIR, new_name))
                except OSError:
                    shutil.move(os.path.join(old_dir, it["key"]), os.path.join(SCRIPT_DIR, it["key"]))
                    raise
        except OSError as e:
            say(f"{RED}{upd_t('apply_err', name=name, e=e)}{RESET}")
            done["e"] += 1
            continue
        if replacing:
            record({"op": "replace", "old": it["key"], "new": new_name, "old_sha256": it.get("sha256"), "new_sha256": it.get("staged_sha256")})
            it["staged"], it["staged_sha256"] = None, None
            done["u"] += 1
            say(f"{GREEN}{upd_t('apply_ok_update', old=it['key'], new=new_name)}{RESET}")
        else:
            record({"op": "drop", "old": it["key"], "old_sha256": it.get("sha256")})
            done["d"] += 1
            say(upd_t("apply_ok_drop", old=it["key"]))
    for it in adds:
        name = upd_cut(it["display"], 30)
        new_name = it.get("staged")
        dest = os.path.join(SCRIPT_DIR, new_name or "")
        if not new_name or not upd_is_staged(it, plan):
            say(f"{YELLOW}{upd_t('apply_skipped_unstaged', name=name)}{RESET}")
            done["e"] += 1
            continue
        if os.path.exists(dest):
            say(f"{YELLOW}{upd_t('apply_conflict', name=name, fn=new_name)}{RESET}")
            done["e"] += 1
            continue
        try:
            os.replace(os.path.join(sdir, new_name), dest)
        except OSError as e:
            say(f"{RED}{upd_t('apply_err', name=name, e=e)}{RESET}")
            done["e"] += 1
            continue
        record({"op": "add", "new": new_name, "new_sha256": it.get("staged_sha256")})
        it["staged"], it["staged_sha256"] = None, None
        done["a"] += 1
        say(f"{GREEN}{upd_t('apply_ok_add', new=new_name)}{RESET}")
    manifest["complete"] = True
    upd_write_json(manifest_path, manifest)
    plan["applied"] = manifest["stamp"]
    plan["stale"] = True
    upd_save()
    say(upd_t("apply_done", u=done["u"], a=done["a"], d=done["d"], e=done["e"], dir=os.path.relpath(bdir, SCRIPT_DIR)))
    say(upd_t("apply_hint"))


def upd_manifests():
    out = []
    if not os.path.isdir(UPDATE_BACKUP_DIR):
        return out
    for name in sorted(os.listdir(UPDATE_BACKUP_DIR), reverse=True):
        path = os.path.join(UPDATE_BACKUP_DIR, name, "manifest.json")
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except (OSError, ValueError):
            continue
        if isinstance(data, dict) and isinstance(data.get("entries"), list):
            out.append((name, path, data))
    return out


# c168
def upd_cmd_rollback():
    todo = [x for x in upd_manifests() if not x[2].get("rolled_back")]
    if not todo:
        say(upd_t("rollback_none"))
        return
    name, mpath, data = todo[0]
    bdir = os.path.dirname(mpath)
    entries = [e for e in data["entries"] if isinstance(e, dict)]
    say(upd_t("rollback_title", stamp=name, n=sum(1 for e in entries if e.get("old"))))
    if not upd_confirm(upd_t("rollback_confirm")):
        say(T[LANG]["cancelled"])
        return
    removed_dir = os.path.join(bdir, "new_removed")
    restored = skipped = 0
    for e in reversed(entries):
        new_name, old_name = e.get("new"), e.get("old")
        if new_name:
            path = os.path.join(SCRIPT_DIR, new_name)
            if os.path.isfile(path):
                try:
                    same = not e.get("new_sha256") or file_sha256(path) == e["new_sha256"]
                    if not same:
                        raise OSError("файл изменён" if LANG == "ru" else "file was changed")
                    os.makedirs(removed_dir, exist_ok=True)
                    shutil.move(path, os.path.join(removed_dir, new_name))
                    say(upd_t("rollback_removed", name=new_name))
                except OSError as ex:
                    skipped += 1
                    say(f"{YELLOW}{upd_t('rollback_skip', name=new_name, why=ex)}{RESET}")
                    continue
        if old_name:
            src, dst = os.path.join(bdir, "old", old_name), os.path.join(SCRIPT_DIR, old_name)
            if not os.path.isfile(src):
                skipped += 1
                say(f"{YELLOW}{upd_t('rollback_skip', name=old_name, why='нет в бэкапе' if LANG == 'ru' else 'not in the backup')}{RESET}")
            elif os.path.exists(dst):
                skipped += 1
                say(f"{YELLOW}{upd_t('rollback_skip', name=old_name, why='имя занято' if LANG == 'ru' else 'name is taken')}{RESET}")
            else:
                try:
                    shutil.move(src, dst)
                    restored += 1
                    say(f"{GREEN}{upd_t('rollback_ok', name=old_name)}{RESET}")
                except OSError as ex:
                    skipped += 1
                    say(f"{YELLOW}{upd_t('rollback_skip', name=old_name, why=ex)}{RESET}")
    data["rolled_back"] = True
    try:
        upd_write_json(mpath, data)
    except OSError:
        pass
    plan = upd_load()
    if plan:
        plan["stale"] = True
        upd_save()
    say(upd_t("rollback_done", n=restored, s=skipped))


def upd_cmd_export(args, plan):
    if not args:
        say(upd_t("export_usage"))
        return
    side = args[1].lower() if len(args) > 1 and args[1].lower() in ("client", "server") else None
    dest = os.path.abspath(args[0] if os.path.isabs(args[0]) else os.path.join(SCRIPT_DIR, args[0]))
    inside = lambda root: dest == root or dest.startswith(root + os.sep)
    if dest == SCRIPT_DIR or inside(UPDATE_STAGE_DIR) or inside(UPDATE_BACKUP_DIR):
        say(f"{RED}{upd_t('export_bad_dir', d=dest)}{RESET}")
        return
    if os.path.isdir(dest) and os.listdir(dest) and not upd_confirm(upd_t("export_not_empty", d=dest)):
        say(upd_t("apply_cancel"))
        return
    os.makedirs(dest, exist_ok=True)
    say(upd_t("export_start", d=dest))
    sdir = upd_stage_dir(plan)
    copied = news = skipped = 0
    used = set()
    for it in plan["items"]:
        act = upd_action(it, plan)
        if act not in ("update", "add", "keep") or it.get("state") == "broken":
            continue
        if side and not it.get("extra") and it.get("side") not in (side, "both", "unknown"):
            continue
        name = upd_cut(it["display"], 30)
        if act in ("update", "add"):
            if not upd_is_staged(it, plan):
                skipped += 1
                say(f"{YELLOW}{upd_t('export_skip_unstaged', name=name)}{RESET}")
                continue
            src, out_name = os.path.join(sdir, it["staged"]), it["staged"]
        else:
            src, out_name = os.path.join(SCRIPT_DIR, it["key"]), it["key"]
            if not os.path.isfile(src):
                skipped += 1
                continue
        if out_name in used:
            skipped += 1
            continue
        try:
            shutil.copy2(src, os.path.join(dest, out_name))
        except OSError as e:
            skipped += 1
            say(f"{RED}{upd_t('apply_err', name=name, e=e)}{RESET}")
            continue
        used.add(out_name)
        copied += 1
        news += 1 if act in ("update", "add") else 0
    say(upd_t("export_done", n=copied, u=news, s=skipped))
    say(upd_t("export_hint"))


def upd_cmd_report(plan):
    mc, loader = plan["target"]["mc"], plan["target"]["loader"]
    lines = [f"Minecraft {mc}, {loader}", f"{upd_now()}", ""]
    c = upd_counts(plan)
    for key in ("ready", "current", "near", "beta", "manual", "nofile", "unknown", "error", "broken", "extras"):
        if c.get(key):
            lines.append(f"{key}: {c[key]}")
    lines.append("")
    numbered = list(enumerate(plan["items"], 1))
    for g, title in (("problems", "grp_problems"), ("ready", "grp_ready"), ("extras", "grp_extras"), ("current", "grp_current")):
        rows = [(n, it) for n, it in numbered if upd_group(it, plan) == g]
        if not rows:
            continue
        lines.append(upd_t(title))
        for n, it in rows:
            lines.append(strip_ansi(upd_line(n, it, plan)))
            if g == "problems":
                q = urllib.parse.quote(str(it.get("display") or ""))
                if it.get("page"):
                    lines.append(f"       {it['page']}")
                lines.append(f"       https://modrinth.com/mods?q={q}")
                lines.append(f"       https://www.curseforge.com/minecraft/search?search={q}")
        lines.append("")
    path = os.path.join(SCRIPT_DIR, f"update_report_{mc}_{loader}.txt")
    try:
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            f.write("\n".join(lines) + "\n")
        os.replace(tmp, path)
    except OSError as e:
        say(f"{RED}{upd_t('report_fail', e=e)}{RESET}")
        return
    say(upd_t("report_done", f=os.path.basename(path)))


def upd_cmd_status():
    plan = upd_load()
    say(f"{GREEN}{BOLD}{upd_t('status_title')}{RESET}")
    if not plan or not plan["items"]:
        say(upd_t("status_none"))
        if plan:
            say(upd_t("target_now", mc=plan["target"]["mc"], loader=plan["target"]["loader"]))
        return
    say(upd_t("status_plan", when=plan.get("planned") or "-", mc=plan["target"]["mc"], loader=plan["target"]["loader"],
              ch="/".join(upd_allowed(plan)), near="on" if plan.get("near") else "off"))
    if plan.get("source"):
        say(upd_t("plan_source", mc=plan["source"]["mc"], loader=plan["source"]["loader"], n=plan["source"]["n"],
                  tmc=plan["target"]["mc"], tloader=plan["target"]["loader"]))
    upd_print_summary(plan)
    want = [it for it in plan["items"] if upd_action(it, plan) in ("update", "add")]
    say(upd_t("status_staged", n=sum(1 for it in want if upd_is_staged(it, plan)), m=len(want)))
    if plan.get("applied"):
        say(upd_t("status_applied", stamp=plan["applied"]))
    left = [x for x in upd_manifests() if not x[2].get("rolled_back")]
    if left:
        say(upd_t("status_rollback", stamp=left[0][0]))


def upd_cmd_clear():
    global UPD
    if not upd_confirm(upd_t("clear_confirm")):
        say(T[LANG]["cancelled"])
        return
    upd_rm(UPDATE_STATE_PATH)
    shutil.rmtree(UPDATE_STAGE_DIR, ignore_errors=True)
    UPD = None
    say(upd_t("clear_done"))


def upd_plan_or_create():
    global UPD
    plan = upd_load()
    if plan:
        return plan
    if TARGET_MC:
        UPD = upd_new_plan(TARGET_MC, API_LOADER if API_LOADER in UPD_LOADERS else "neoforge")
        return UPD
    return None


def upd_cmd_plan(args, api_key):
    fresh = False
    toks = []
    for a in args:
        if a.lower() in ("fresh", "new", "--fresh"):
            fresh = True
        else:
            toks.append(a)
    if toks:
        current = upd_load()
        loader = toks[1].lower() if len(toks) > 1 else (current["target"]["loader"] if current else API_LOADER)
        if not upd_set_target(toks[0], loader):
            return
    plan = upd_plan_or_create()
    if not plan:
        say(upd_t("need_target"))
        return
    upd_build(plan, api_key, fresh)


def upd_dispatch(sub, args, api_key):
    sub = UPD_ALIASES.get(sub, sub)
    if sub == "help":
        for line in upd_t("help"):
            say(line)
        return
    if sub == "target":
        upd_cmd_target(args)
        return
    if sub == "plan":
        upd_cmd_plan(args, api_key)
        return
    if sub == "rollback":
        upd_cmd_rollback()
        return
    if sub == "clear":
        upd_cmd_clear()
        return
    if sub == "status":
        upd_cmd_status()
        return
    if sub not in UPD_SUBS:
        say(upd_t("unknown_sub", v=sub))
        return
    if sub in ("channel", "near"):
        plan = upd_plan_or_create()
        if not plan:
            say(upd_t("need_target"))
            return
        (upd_cmd_channel if sub == "channel" else upd_cmd_near)(args, plan)
        return
    plan = upd_need_plan()
    if not plan:
        return
    if sub == "list":
        upd_cmd_list(args, plan)
    elif sub == "show":
        upd_cmd_show(args, plan)
    elif sub == "pick":
        upd_cmd_pick(args, plan)
    elif sub in ("keep", "drop", "reset"):
        upd_cmd_mark(sub, args, plan)
    elif sub == "stage":
        upd_cmd_stage(plan)
    elif sub == "apply":
        upd_cmd_apply(args, plan)
    elif sub == "export":
        upd_cmd_export(args, plan)
    elif sub == "report":
        upd_cmd_report(plan)


def upd_safe_dispatch(sub, args, api_key):
    try:
        upd_dispatch(sub, args, api_key)
    except KeyboardInterrupt:
        say(f"\n{YELLOW}{T[LANG]['cancelled']}{RESET}")
    except Exception as exc:
        say(f"{RED}{upd_t('err_cmd', cmd=sub, e=f'{type(exc).__name__}: {exc}')}{RESET}")
        try:
            log_command_crash("update " + sub, exc)
        except NameError:
            pass


def update_menu(api_key):
    say(f"{GREEN}{BOLD}{upd_t('menu_title')}{RESET}")
    plan = upd_load()
    if plan and plan["items"]:
        upd_print_summary(plan)
    else:
        say(upd_t("no_plan"))
        if plan or TARGET_MC:
            mc = plan["target"]["mc"] if plan else TARGET_MC
            loader = plan["target"]["loader"] if plan else API_LOADER
            say(upd_t("target_now", mc=mc, loader=loader))
    say(f"{DIM}{upd_t('menu_hint')}{RESET}")
    while True:
        try:
            line = input(upd_t("menu_prompt")).strip()
        except (EOFError, KeyboardInterrupt, ValueError):
            print()
            break
        log_console_raw(f"> {line}")
        if not line:
            continue
        parts = line.split()
        if parts[0].lower() == "update" and len(parts) > 1:
            parts = parts[1:]
        cmd = parts[0].lower()
        if cmd in ("q", "quit", "exit", "back", "выход", "в"):
            break
        if re.fullmatch(r"\d+(-\d+)?", cmd):
            upd_safe_dispatch("show", parts, api_key)
        else:
            upd_safe_dispatch(cmd, parts[1:], api_key)


def do_update_center(rest, api_key):
    global _UPD_API_KEY
    _UPD_API_KEY = api_key
    parts = rest.split()
    if not parts:
        update_menu(api_key)
        return
    sub = parts[0].lower()
    if sub in UPD_SUBS or sub == "download":
        upd_safe_dispatch("stage" if sub == "download" else sub, parts[1:], api_key)
        return
    do_update(["all"] if rest.strip().lower() == "all" else [rest.strip()], api_key)


def build_report_html(tr, update_rows, scan_findings):
    def esc(s):
        return html_esc.escape(str(s) if s is not None else "")

    def h(key):
        return esc(tr[key].strip(" ="))

    mods = LAST_RUN["mods"]
    valid_mods = [m for m in mods if not m["error"]]
    counts = {"client": 0, "server": 0, "both": 0, "unknown": 0}
    for m in valid_mods:
        counts[m.get("side_class", "unknown")] += 1
    total_jar = sum(1 for f in os.listdir(SCRIPT_DIR) if f.endswith(".jar") and os.path.isfile(os.path.join(SCRIPT_DIR, f)))
    broken = sum(1 for m in mods if is_broken(m))
    missing_toml = sum(1 for m in mods if m["error"] == tr["err_toml_missing"])
    duplicates = [files for files in LAST_RUN["modid_files"].values() if len(files) > 1]
    required_missing = LAST_RUN["required_missing"]
    optional_missing = LAST_RUN["optional_missing"]
    incompatibilities = LAST_RUN.get("incompatibilities", [])

    generated = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
    target_line = f"{esc(TARGET_MC)} / {esc(TARGET_LOADER)}" if (TARGET_MC or TARGET_LOADER) else "-"

    def stat_card(label, value):
        return f'<div class="card"><div class="card-value">{esc(value)}</div><div class="card-label">{esc(label)}</div></div>'

    stats_html = "".join([
        stat_card(tr["stats_total"], total_jar),
        stat_card(tr["stats_valid"], len(valid_mods)),
        stat_card(tr["stats_broken"], broken),
        stat_card(tr["stats_missing_toml"], missing_toml),
        stat_card(tr["stats_client"], counts["client"]),
        stat_card(tr["stats_server"], counts["server"]),
        stat_card(tr["stats_both"], counts["both"]),
        stat_card(tr["stats_unknown"], counts["unknown"]),
        stat_card(tr["stats_required"], len(required_missing)),
        stat_card(tr["stats_optional"], len(optional_missing)),
        stat_card(tr["stats_conflicts"], len(incompatibilities)),
        stat_card(tr["stats_duplicates"], len(duplicates)),
        stat_card(tr["stats_identical"], len(LAST_RUN["identical_files"])),
        stat_card(tr["stats_disabled"], len(LAST_RUN["disabled_names"])),
    ])

    side_label_map = {"client": "CLIENT", "server": "SERVER", "both": "BOTH", "unknown": "?"}
    mod_rows = []
    for m in sorted(valid_mods, key=lambda x: x["display"].lower()):
        data = m.get("data")
        version = data["mods"][0].get("version") if data and data.get("mods") else "?"
        side_class_css = m.get("side_class", "unknown")
        side = side_label_map.get(side_class_css, "?")
        sources = []
        if m.get("modrinth_id"):
            sources.append("Modrinth")
        if m.get("cf_slug"):
            sources.append("CurseForge")
        sha = (m.get("sha256") or "")[:12]
        mod_rows.append(
            f"<tr><td>{esc(m['display'])}</td><td>{esc(m.get('modid') or '?')}</td>"
            f"<td>{esc(version)}</td><td><span class='side side-{esc(side_class_css)}'>{esc(side)}</span></td>"
            f"<td>{esc(', '.join(sources) or '-')}</td><td class='mono'>{esc(sha or '-')}</td></tr>"
        )
    broken_rows = "".join(
        f"<tr><td>{esc(m['fname'])}</td><td>{esc(m['error'])}</td></tr>" for m in mods if is_broken(m)
    )

    req_html = "".join(
        f"<li><b>{esc(dep_modid)}</b>, {esc(tr['required_for'])}: {esc(', '.join(sorted(needers)))}</li>"
        for dep_modid, needers in sorted(required_missing.items())
    ) or f"<li class='muted'>{esc(tr['no_required'])}</li>"
    opt_html = "".join(
        f"<li><b>{esc(dep_modid)}</b>, {esc(tr['optional_for'])}: {esc(', '.join(sorted(needers)))}</li>"
        for dep_modid, needers in sorted(optional_missing.items())
    ) or f"<li class='muted'>{esc(tr['no_optional'])}</li>"
    conflict_html = "".join(
        f"<li><b>{esc(a_display)}</b> [{esc(a_id)}] &lt;-&gt; <b>{esc(b_display)}</b> [{esc(b_id)}]"
        f"{(', ' + esc(reason)) if reason else ''}</li>"
        for a_display, a_id, b_display, b_id, reason in incompatibilities
    ) or f"<li class='muted'>{esc(tr['no_incompatible'])}</li>"

    if update_rows:
        update_html = ("<table><tr><th>Mod</th><th>" + h("updates_installed") + "</th><th>"
                        + h("updates_latest") + "</th><th>" + h("install_source") + "</th></tr>" + "".join(
            f"<tr><td>{esc(name)}</td><td>{esc(inst)}</td><td>{esc(latest)}</td><td>{esc(source)}</td></tr>"
            for name, inst, latest, source, _status in update_rows
        ) + "</table>")
    elif LAST_RUN["internet"]:
        update_html = f"<p class='muted'>{esc(tr['updates_uptodate'])}</p>"
    else:
        update_html = f"<p class='muted'>{esc(tr['no_internet'])}</p>"

    if scan_findings:
        scan_html = ""
        order = sorted(scan_findings, key=lambda f: min(SEVERITY_ORDER[s] for s, _, _ in scan_findings[f]))
        for fname in order:
            items = "".join(
                f"<li><span class='sev sev-{sev.lower()}'>[{sev}]</span> {esc(tr[SCAN_LABEL_KEYS[key]])}: {esc(detail)}</li>"
                for sev, key, detail in sorted(scan_findings[fname], key=lambda x: SEVERITY_ORDER[x[0]])
            )
            scan_html += f"<div class='scan-file'><b>{esc(fname)}</b><ul>{items}</ul></div>"
    else:
        scan_html = f"<p class='muted'>{esc(tr['scan_none'])}</p>"

    broken_section = ""
    if broken_rows:
        broken_section = (f"<h2>{h('report_broken_label')}</h2><table><tr><th>File</th><th>Error</th></tr>"
                           f"{broken_rows}</table>")

    return f"""<!DOCTYPE html>
<html lang="{'ru' if LANG == 'ru' else 'en'}">
<head>
<meta charset="utf-8">
<title>Modpack Report {esc(generated)}</title>
<style>
  :root {{ color-scheme: dark; }}
  body {{ background:#14151a; color:#e6e6ea; font-family: -apple-system, "Segoe UI", Roboto, Arial, sans-serif; margin:0; padding:2rem; line-height:1.5; }}
  h1 {{ margin-top:0; }}
  h2 {{ border-bottom:1px solid #333; padding-bottom:.4rem; margin-top:2.5rem; }}
  .meta {{ color:#9a9aa5; margin-bottom:2rem; }}
  .grid {{ display:grid; grid-template-columns: repeat(auto-fill, minmax(140px,1fr)); gap:.75rem; }}
  .card {{ background:#1d1e25; border:1px solid #2a2b33; border-radius:10px; padding:1rem; text-align:center; }}
  .card-value {{ font-size:1.6rem; font-weight:700; }}
  .card-label {{ color:#9a9aa5; font-size:.8rem; margin-top:.25rem; }}
  table {{ width:100%; border-collapse:collapse; margin-top:1rem; font-size:.9rem; }}
  th, td {{ text-align:left; padding:.5rem .6rem; border-bottom:1px solid #2a2b33; }}
  th {{ color:#9a9aa5; font-weight:600; }}
  tr:hover td {{ background:#1d1e25; }}
  .mono {{ font-family: ui-monospace, Consolas, monospace; font-size:.8rem; color:#9a9aa5; }}
  .side {{ padding:.15rem .5rem; border-radius:6px; font-size:.75rem; font-weight:700; }}
  .side-client {{ background:#4a3a10; color:#f5c451; }}
  .side-server {{ background:#123a24; color:#4fd67f; }}
  .side-both {{ background:#12303a; color:#4fc3d6; }}
  .side-unknown {{ background:#333; color:#aaa; }}
  ul {{ padding-left:1.2rem; }}
  li {{ margin:.25rem 0; }}
  .muted {{ color:#9a9aa5; }}
  .scan-file {{ background:#1d1e25; border:1px solid #2a2b33; border-radius:10px; padding:.75rem 1rem; margin-bottom:.6rem; }}
  .sev {{ font-weight:700; }}
  .sev-high {{ color:#ff6b6b; }}
  .sev-medium {{ color:#f5c451; }}
  .sev-low {{ color:#4fd67f; }}
</style>
</head>
<body>
<h1>Modpack Report</h1>
<div class="meta">{h('report_generated_label')}: {esc(generated)} &middot; {h('report_target_label')}: {target_line}</div>

<h2>{h('header_stats')}</h2>
<div class="grid">{stats_html}</div>

<h2>{h('report_mods_label')}</h2>
<table>
<tr><th>{h('explain_id')}</th><th>ModID</th><th>{h('explain_version')}</th><th>Side</th><th>{h('explain_sources')}</th><th>SHA256</th></tr>
{''.join(mod_rows)}
</table>

{broken_section}

<h2>{h('header_required')}</h2>
<ul>{req_html}</ul>

<h2>{h('header_optional')}</h2>
<ul>{opt_html}</ul>

<h2>{h('header_incompatible')}</h2>
<ul>{conflict_html}</ul>

<h2>{h('updates_header')}</h2>
{update_html}

<h2>{h('header_scan')}</h2>
<p class="muted">{esc(tr['scan_disclaimer'])}</p>
{scan_html}

</body>
</html>
"""


# c170
def do_report(api_key):
    tr = T[LANG]
    if not LAST_RUN:
        say(tr["run_first"])
        return
    say(tr["report_building"])

    update_rows = []
    if LAST_RUN["internet"]:
        for m in LAST_RUN["mods"]:
            if m["error"] or not m.get("modid") or not (m.get("modrinth_id") or m.get("cf_id")):
                continue
            data = m["data"]
            version = data["mods"][0].get("version") if data and data.get("mods") else None
            status, latest, source = check_update(version, m.get("modrinth_id"), m.get("cf_id"), api_key)
            if status in ("update", "major"):
                update_rows.append((m["display"], version or "?", latest or "?", source or "?", status))

    scan_findings = collect_scan_findings()
    html_out = build_report_html(tr, update_rows, scan_findings)

    report_path = os.path.join(SCRIPT_DIR, "modpack_report.html")
    try:
        with open(report_path, "w", encoding="utf-8") as f:
            f.write(html_out)
        say(tr["report_done"].format(path="modpack_report.html"))
    except OSError as e:
        say(f"{RED}{e}{RESET}")
    say(tr["commands"])


HELP_RAIL = "¦"
HELP_SPLIT = re.compile(r"(?<=[.!?])\s+(?=[A-ZА-ЯЁ])")


def help_lines(desc, width):
    out = []
    for part in str(desc).split("\n"):
        for sent in HELP_SPLIT.split(part.strip()):
            if not sent:
                continue
            for i, piece in enumerate(textwrap.wrap(sent, width) or [""]):
                out.append(("  " if i else "") + piece)
    return out


def do_help():
    tr = T[LANG]
    cols = shutil.get_terminal_size((100, 24)).columns
    width = max(40, min(cols, 100) - 8)
    say(f"{GREEN}{BOLD}{tr['help_header']}{RESET}")
    for group_title, rows in HELP_GROUPS[LANG]:
        say()
        say(f"{GREEN}{BOLD}§ {group_title}{RESET}")
        for cmd, desc in rows:
            say()
            say(f"  {BOLD}{cmd}{RESET}")
            for line in help_lines(desc, width):
                say(f"    {HELP_RAIL} {line}")
    _do_auto_finder_help()


def list_snapshots():
    if not os.path.isdir(LOGS_DIR):
        return []
    return sorted(f for f in os.listdir(LOGS_DIR) if f.endswith(".snapshot.json"))

def load_snapshot(fname):
    try:
        with open(os.path.join(LOGS_DIR, fname), "r", encoding="utf-8") as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError):
        return None

def do_logs():
    tr = T[LANG]
    files = list_snapshots()
    say(f"{GREEN}{BOLD}{tr['logs_header']}{RESET}")
    if not files:
        say(tr["logs_none"])
        return
    for idx, fname in enumerate(files, start=1):
        say(f"  [{idx}] {fname}")
    say(tr["commands"])

def snapshot_ts(fname):
    try:
        return int(fname.split("_", 1)[0])
    except ValueError:
        return 0

def do_timeline():
    tr = T[LANG]
    files = list_snapshots()  # c089
    if not files:
        say(f"{RED}{tr['timeline_none']}{RESET}")
        return

    out_lines = []
    header = f"{GREEN}{BOLD}{tr['header_timeline']}{RESET}"
    say(header)
    out_lines.append(strip_ansi(header))

    prev_snap = None
    for fname in files:
        snap = load_snapshot(fname)
        if snap is None:
            continue
        ts = snapshot_ts(fname)
        dt_str = datetime.datetime.fromtimestamp(ts).strftime("%d.%m.%Y %H:%M") if ts else fname

        say()
        out_lines.append("")

        entry_header = f"{BOLD}{dt_str}{RESET}"
        say(entry_header)
        out_lines.append(dt_str)

        count_line = f"{len(snap)} {tr['timeline_mods_word']}"
        say(count_line)
        out_lines.append(count_line)

        if prev_snap is not None:
            old_ids, new_ids = set(prev_snap), set(snap)
            added = sorted(new_ids - old_ids)
            removed = sorted(old_ids - new_ids)
            common = sorted(old_ids & new_ids)

            for modid in added:
                display = snap[modid].get("display", modid)
                line = f"{GREEN}+ {display} [{modid}], {tr['timeline_added_word']}{RESET}"
                say(line)
                out_lines.append(strip_ansi(line))

            for modid in removed:
                display = prev_snap[modid].get("display", modid)
                line = f"{RED}- {display} [{modid}], {tr['timeline_removed_word']}{RESET}"
                say(line)
                out_lines.append(strip_ansi(line))

            for modid in common:
                o, n = prev_snap[modid], snap[modid]
                display = n.get("display", modid)

                if o.get("version") and n.get("version") and o.get("version") != n.get("version"):
                    text = tr["timeline_updated_word"].format(name=display, old=o.get("version"), new=n.get("version"))
                    line = f"{YELLOW}~ {text}{RESET}"
                    say(line)
                    out_lines.append(strip_ansi(line))

                side_known = o.get("client_side") is not None and n.get("client_side") is not None
                if side_known and (o.get("client_side") != n.get("client_side") or o.get("server_side") != n.get("server_side")):
                    text = tr["timeline_side_changed"].format(name=display)
                    line = f"{YELLOW}! {text}{RESET}"
                    say(line)
                    out_lines.append(strip_ansi(line))

        prev_snap = snap

    say()
    out_lines.append("")

    try:
        os.makedirs(TIMELINE_DIR, exist_ok=True)
        existing = [f for f in os.listdir(TIMELINE_DIR) if f.startswith("timeline") and f.endswith(".txt")]
        idx = len(existing) + 1
        date_str = datetime.datetime.now().strftime("%Y-%m-%d")
        out_name = f"timeline{idx}-{date_str}.txt"
        out_path = os.path.join(TIMELINE_DIR, out_name)
        with open(out_path, "w", encoding="utf-8") as f:
            f.write("\n".join(out_lines))
        say(f"[{tr['timeline_saved']}: {out_path}]")
    except OSError:
        pass

    say(tr["commands"])

def do_compare(args):
    tr = T[LANG]
    files = list_snapshots()
    if len(files) < 2:
        say(f"{RED}{tr['compare_need_two']}{RESET}")
        return

    if len(args) == 1 and args[0].isdigit():
        n = max(2, min(int(args[0]), len(files)))
        old_file, new_file = files[-n], files[-1]
    elif len(args) == 2 and args[0].lower().startswith("file") and args[1].lower().startswith("file"):
        try:
            i1 = int(args[0][4:])
            i2 = int(args[1][4:])
        except ValueError:
            say(f"{RED}{tr['compare_bad_args']}{RESET}")
            return
        if not (1 <= i1 <= len(files)) or not (1 <= i2 <= len(files)):
            say(f"{RED}{tr['compare_bad_index']}{RESET}")
            return
        old_file, new_file = (files[i1 - 1], files[i2 - 1]) if i1 <= i2 else (files[i2 - 1], files[i1 - 1])
    else:
        say(f"{RED}{tr['compare_bad_args']}{RESET}")
        return

    old_snap = load_snapshot(old_file) or {}
    new_snap = load_snapshot(new_file) or {}

    old_ids, new_ids = set(old_snap), set(new_snap)
    added = new_ids - old_ids
    deleted = old_ids - new_ids
    common = old_ids & new_ids

    changed = []
    updated = []
    for modid in sorted(common):
        o, n = old_snap[modid], new_snap[modid]
        side_known = o.get("client_side") is not None and n.get("client_side") is not None
        if side_known and (o.get("is_client_only") != n.get("is_client_only")
                            or o.get("client_side") != n.get("client_side")
                            or o.get("server_side") != n.get("server_side")):
            changed.append((modid, n.get("display", modid), o, n))
        if o.get("version") and n.get("version") and o.get("version") != n.get("version"):
            updated.append((modid, n.get("display", modid), o.get("version"), n.get("version")))

    say(f"{GREEN}{BOLD}{tr['compare_header'].format(old=old_file, new=new_file)}{RESET}")

    say(tr["compare_added"])
    if added:
        for modid in sorted(added):
            say(f"  {new_snap[modid].get('display', modid)} [{modid}]")
    else:
        say(tr["compare_empty"])

    say(tr["compare_deleted"])
    if deleted:
        for modid in sorted(deleted):
            say(f"  {old_snap[modid].get('display', modid)} [{modid}]")
    else:
        say(tr["compare_empty"])

    say(tr["compare_changed"])
    if changed:
        for modid, display, o, n in changed:
            say(f"  {display} [{modid}]: client={o.get('client_side')}->{n.get('client_side')}, server={o.get('server_side')}->{n.get('server_side')}")
    else:
        say(tr["compare_empty"])

    say(tr["compare_updated"])
    if updated:
        for modid, display, ov, nv in updated:
            say(f"  {display} [{modid}]: {ov} -> {nv}")
    else:
        say(tr["compare_empty"])
    say(tr["commands"])


def scan_build_folder(folder):
    root = os.path.abspath(os.path.expanduser(folder))
    if not os.path.isdir(root):
        raise NotADirectoryError(root)
    records = {}
    for current, dirs, files in os.walk(root):
        dirs[:] = [d for d in dirs if d not in (".git", "__pycache__", "update_backup", "update_stage")]
        for filename in sorted(files):
            if not filename.lower().endswith(".jar"):
                continue
            path = os.path.join(current, filename)
            rel = os.path.relpath(path, root)
            try:
                sha256 = file_sha256(path)
                with zipfile.ZipFile(path) as jar:
                    names = jar.namelist()
                    data = load_meta(jar, names)
                    meta = read_artifact_meta(jar, names, data)
            except (OSError, zipfile.BadZipFile, RuntimeError, zlib.error, EOFError, NotImplementedError):
                data, meta, sha256 = None, {}, None
            mods = data.get("mods") if isinstance(data, dict) else None
            entry = mods[0] if isinstance(mods, list) and mods and isinstance(mods[0], dict) else {}
            modid = entry.get("modId") if isinstance(entry.get("modId"), str) else None
            display = entry.get("displayName") if isinstance(entry.get("displayName"), str) else None
            version = entry.get("version")
            if version is None and isinstance(meta, dict):
                manifest = meta.get("manifest") or {}
                version = manifest.get("implementation-version") or manifest.get("specification-version")
            if not display:
                names_from_meta = meta.get("names") if isinstance(meta, dict) else []
                display = names_from_meta[0] if names_from_meta else os.path.splitext(filename)[0]
            if not modid:
                identity = "name:" + re.sub(r"[\W_]+", "", str(display).casefold())
            else:
                identity = "id:" + modid.casefold()
            if identity in records:
                identity += "#" + rel.casefold()
            records[identity] = {"modid": modid, "display": str(display),
                                 "version": str(version) if version is not None else None,
                                 "sha256": sha256, "file": rel}
    return records


def do_build_compare(args):
    if len(args) != 2:
        say(_t("Использование: buildcompare <папка_сборки_1> <папка_сборки_2>",
               "Usage: buildcompare <build_folder_1> <build_folder_2>"))
        return
    try:
        old = scan_build_folder(args[0])
        new = scan_build_folder(args[1])
    except (OSError, NotADirectoryError) as exc:
        say(f"{RED}{exc}{RESET}")
        return
    old_keys, new_keys = set(old), set(new)
    added = sorted(new_keys - old_keys, key=lambda k: new[k]["display"].casefold())
    removed = sorted(old_keys - new_keys, key=lambda k: old[k]["display"].casefold())
    changed = []
    for key in sorted(old_keys & new_keys):
        before, after = old[key], new[key]
        if before.get("version") != after.get("version") or before.get("sha256") != after.get("sha256"):
            changed.append((before, after))
    lines = [f"=== Build comparison: {os.path.abspath(args[0])} -> {os.path.abspath(args[1])} ===",
             f"Old: {len(old)} jars | New: {len(new)} jars", "", "ADDED"]
    say(f"{GREEN}{BOLD}=== Сравнение папок сборок ==={RESET}")
    say(f"{_t('Было', 'Old')}: {len(old)} JAR | {_t('Стало', 'New')}: {len(new)} JAR")
    for key in added:
        row = new[key]
        text = f"+ {row['display']} [{row.get('modid') or '?'}] {row.get('version') or '?'} — {row['file']}"
        say(GREEN + text + RESET)
        lines.append(text)
    lines += ["", "REMOVED"]
    say(_t("Удалены:", "Removed:"))
    for key in removed:
        row = old[key]
        text = f"- {row['display']} [{row.get('modid') or '?'}] {row.get('version') or '?'} — {row['file']}"
        say(RED + text + RESET)
        lines.append(text)
    lines += ["", "CHANGED"]
    say(_t("Изменились:", "Changed:"))
    for before, after in changed:
        parts = []
        if before.get("version") != after.get("version"):
            parts.append(f"version {before.get('version') or '?'} -> {after.get('version') or '?'}")
        if before.get("sha256") != after.get("sha256"):
            parts.append("JAR hash changed")
        text = f"~ {after['display']} [{after.get('modid') or '?'}]: " + ", ".join(parts)
        say(YELLOW + text + RESET)
        lines.append(text)
    if not added and not removed and not changed:
        text = _t("Состав и файлы совпадают.", "Inventories and files match.")
        say(GREEN + text + RESET)
        lines.append(text)
    say(_t("Совпадающие моды не перечислены.", "Unchanged mods are omitted."))
    try:
        os.makedirs(LOGS_DIR, exist_ok=True)
        out = os.path.join(LOGS_DIR, "build_compare_" + datetime.datetime.now().strftime("%Y%m%d_%H%M%S") + ".txt")
        with open(out, "w", encoding="utf-8") as f:
            f.write("\n".join(lines) + "\n")
        say(_t('Отчёт сохранён: ', "Report saved: ") + out)
    except OSError:
        pass


def load_cf_key():
    try:
        with open(CF_KEY_PATH, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                return line
    except OSError:
        return None
    return None

def save_cf_key(value):
    try:
        with open(CF_KEY_PATH, "w", encoding="utf-8") as f:
            f.write(CF_KEY_HEADER)
            f.write(value.strip() + "\n")
        try:
            os.chmod(CF_KEY_PATH, 0o600)  # c090
        except OSError:
            pass
    except OSError:
        pass


def print_banner():
    tr = T[LANG]
    say("\n" * 40)
    say(f"{GREEN}{BOLD}#==============================================#{RESET}")
    say(f"{GREEN}{BOLD}{tr['banner_title']}{RESET}")
    say("  https://discord.com/invite/9KmaCbz9HQ")
    say()
    say(f"{BOLD}{tr['banner_verify']}{RESET}")
    say(tr["banner_vt"])
    say(tr["banner_gemini"])
    say(f"{GREEN}{BOLD}#==============================================#{RESET}")
    say()
    say(f"{BOLD}{tr['banner_guide']}{RESET}")
    say(tr["banner_guide1"])
    say(tr["banner_guide2"])
    say(tr["banner_guide3"])
    say(tr["banner_key_note"])
    say()
    say(tr["commands"])

def choose_language():
    global LANG
    while True:
        try:
            choice = input("Выберите язык / Choose language [ru/en]: ").strip().lower()
        except EOFError:
            LANG = "ru"
            return
        log_console_raw(f"> {choice}")
        if choice in ("ru", "en"):
            LANG = choice
            return
        if not choice:
            LANG = "ru"
            return

# c091

MODUL_STATE_PATH = os.path.join(SCRIPT_DIR, ".auto_modpacker_modules.json")
MODUL_DATA_DIR = os.path.join(SCRIPT_DIR, "modul_data")
MODUL_MANUAL_PATH = os.path.join(SCRIPT_DIR, "MODUL_MANUAL.txt")
MODUL_EXT = (".py", ".txt")
MODUL_KEYS = ("idname", "idmodul", "iddescription", "idversion")
MODUL_ALL_KEYS = MODUL_KEYS + ("idperms",)
MODUL_MODES = ("strict", "on", "off")
MODUL_EVENTS = ("start", "run_done", "command", "exit")
MODUL_BUILTIN_CMDS = {
    "key", "run", "logs", "timeline", "compare", "buildcompare", "aternos", "stats", "explain",
    "disable", "enable", "rename", "unrename", "remove", "export", "crash",
    "crashlog", "graphic", "orphan", "scan", "dupres", "clean", "version",
    "updates", "install", "update", "report", "help", "exit", "modul",
}
#F Auto-Finder commands are built-ins too; modules cannot shadow them.
MODUL_BUILTIN_CMDS.update({
    "search", "show", "save", "saveall", "bulk", "addons", "build",
    "newaddons", "importlink", "modupdate", "finder",
})
MODUL_HEADER_RE = re.compile(r"^\s*#?\s*(id[a-z]+)\s*=(.*)$", re.I)
MODUL_ID_RE = re.compile(r"[a-z0-9_]{1,32}")
MODUL_CTRL_RE = re.compile("[\x00-\x08\x0b-\x1f\x7f-\x9f\u200b-\u200f\u202a-\u202e\u2066-\u2069]")
MODUL_MAX_FILE = 1024 * 1024
MODUL_COLORS = {"red": RED, "green": GREEN, "yellow": YELLOW, "bold": BOLD, "dim": DIM}

MODUL_STATE = {"security": "on", "disclaimer_ok": False, "enabled": {}, "unprotected": {}}  # c094
MODUL_LOADED = {}
MODUL_COMMANDS = {}
MODUL_NOTES = {}


def mtext(ru, en):
    return ru if LANG == "ru" else en


def modul_clean_text(text):
    return MODUL_CTRL_RE.sub("", strip_ansi(str(text)))[:4000]


def modul_one_line(text, limit):
    return modul_clean_text(text).replace("\n", " ").strip()[:limit]


def modul_ask(prompt):
    try:
        answer = input(prompt).strip()
    except EOFError:
        return ""
    log_console_raw(f"> {answer}")
    return answer


def modul_confirm(prompt):
    return modul_ask(prompt).lower() in ("yes", "y", "да")


# c101

def modul_load_state():
    global MODUL_STATE
    data = {}
    try:
        with open(MODUL_STATE_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, ValueError):
        data = {}
    if not isinstance(data, dict):
        data = {}
    security = data.get("security")
    if security not in MODUL_MODES:
        security = "on"
    enabled = data.get("enabled")
    if not isinstance(enabled, dict):
        enabled = {}
    unprotected = {}
    raw_grants = data.get("unprotected")
    if isinstance(raw_grants, dict):
        for mid, item in raw_grants.items():
            if isinstance(mid, str) and MODUL_ID_RE.fullmatch(mid) and isinstance(item, dict) \
                    and isinstance(item.get("sha"), str) and item["sha"]:
                unprotected[mid] = {"sha": item["sha"], "time": str(item.get("time", ""))[:20]}
    MODUL_STATE = {"security": security, "disclaimer_ok": bool(data.get("disclaimer_ok")), "enabled": enabled, "unprotected": unprotected}


def modul_save_state():
    tmp = MODUL_STATE_PATH + ".new"
    try:
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(MODUL_STATE, f, ensure_ascii=False, indent=1)
        os.replace(tmp, MODUL_STATE_PATH)
    except OSError:
        say(f"{RED}" + mtext("Не удалось сохранить настройки модулей.", "Could not save module settings.") + RESET)



def modul_decode(raw):
    text = raw.decode("utf-8-sig", "replace")
    return text.replace("\r\n", "\n").replace("\r", "\n")


def modul_clean_value(value):
    value = value.strip()
    if value[:1] in ("'", '"'):
        end = value.find(value[0], 1)
        if end > 0:
            return value[1:end]
    return value


def modul_parse_header(text):
    # c103
    fields = {}
    used = 0
    for i, line in enumerate(text.split("\n")[:60]):
        stripped = line.strip()
        if not stripped:
            continue
        m = MODUL_HEADER_RE.match(line)
        key = m.group(1).lower() if m else ""
        if key in MODUL_ALL_KEYS:
            fields[key] = modul_clean_value(m.group(2))
            used = i + 1
        elif stripped.startswith("#"):
            continue
        else:
            break
    return fields, used


def modul_strip_header(text):
    lines = text.split("\n")
    _fields, used = modul_parse_header(text)
    for i in range(used):
        m = MODUL_HEADER_RE.match(lines[i])
        if m and m.group(1).lower() in MODUL_ALL_KEYS:
            lines[i] = ""
    return "\n".join(lines)


def modul_scan():
    # c105
    recs = []
    used_ids = set()
    try:
        names = sorted(os.listdir(SCRIPT_DIR))
    except OSError:
        return recs
    for fname in names:
        path = os.path.join(SCRIPT_DIR, fname)
        if fname.startswith(".") or not fname.lower().endswith(MODUL_EXT):
            continue
        if path == CF_KEY_PATH or not os.path.isfile(path):
            continue
        try:
            with open(path, "rb") as f:
                head = f.read(4096)
        except OSError:
            continue
        fields, _used = modul_parse_header(modul_decode(head))
        if not all(k in fields for k in MODUL_KEYS):
            continue
        rec = {
            "file": modul_one_line(fname, 80),
            "path": path,
            "id": modul_one_line(fields["idmodul"], 40),
            "name": modul_one_line(fields["idname"], 40),
            "desc": modul_one_line(fields["iddescription"], 200),
            "ver": modul_one_line(fields["idversion"], 20),
            "declared": [p.lower() for p in re.split(r"[,\s;]+", fields.get("idperms", "")) if p],
            "error": None,
            "size": 0,
            "sha": "",
            "text": "",
        }
        if not MODUL_ID_RE.fullmatch(rec["id"]):
            rec["error"] = mtext("idmodul: только a-z, 0-9 и _ (до 32 символов)", "idmodul: only a-z, 0-9 and _ (up to 32 chars)")
        elif rec["id"] in used_ids:
            rec["error"] = mtext("такой idmodul уже есть в другом файле", "this idmodul is already used by another file")
        else:
            used_ids.add(rec["id"])
            try:
                with open(path, "rb") as f:
                    raw = f.read(MODUL_MAX_FILE + 1)
            except OSError:
                raw = b""
                rec["error"] = mtext("файл не читается", "cannot read the file")
            if len(raw) > MODUL_MAX_FILE:
                rec["error"] = mtext("файл больше 1 МБ", "file is bigger than 1 MB")
            rec["size"] = len(raw)
            rec["sha"] = hashlib.sha256(raw).hexdigest()
            rec["text"] = modul_decode(raw)
        recs.append(rec)
    return recs


def modul_pick(token, recs):
    token = token.strip()
    if token.isdigit():
        n = int(token)
        if 1 <= n <= len(recs):
            return recs[n - 1]
        return None
    for rec in recs:
        if token.lower() in (rec["id"].lower(), rec["file"].lower()):
            return rec
    return None



def modul_copy_last_run():
    if not LAST_RUN:
        return None
    mods = []
    for m in LAST_RUN.get("mods", []):
        version = ""
        try:
            version = str(m["data"]["mods"][0].get("version", ""))
        except (KeyError, IndexError, TypeError, AttributeError):
            pass
        mods.append({
            "file": str(m.get("fname", "")),
            "modid": m.get("modid"),
            "name": str(m.get("display", "")),
            "version": version,
            "side": m.get("side_class", "unknown"),
            "error": m.get("error"),
        })
    missing = {}
    for modid, needers in LAST_RUN.get("required_missing", {}).items():
        missing[str(modid)] = sorted(str(x) for x in needers)
    return {
        "internet": bool(LAST_RUN.get("internet")),
        "mods": mods,
        "local_modids": sorted(str(x) for x in LAST_RUN.get("local_modids", [])),
        "required_missing": missing,
    }


def modul_storage_load(mid, default):
    try:
        with open(os.path.join(MODUL_DATA_DIR, mid + ".json"), "r", encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return default


def modul_storage_save(mid, data):
    text = json.dumps(data, ensure_ascii=False)
    if len(text.encode("utf-8")) > 64 * 1024:
        raise ValueError(mtext("данные больше 64 КБ", "data is bigger than 64 KB"))
    os.makedirs(MODUL_DATA_DIR, exist_ok=True)
    path = os.path.join(MODUL_DATA_DIR, mid + ".json")
    with open(path + ".new", "w", encoding="utf-8") as f:
        f.write(text)
    os.replace(path + ".new", path)


# c112

class ModulAPI:
    def __init__(self, handle, mode):
        object.__setattr__(self, "_h", handle)
        object.__setattr__(self, "_mode", mode)
        if mode == "off":
            object.__setattr__(self, "raw", globals())
            object.__setattr__(self, "script_dir", SCRIPT_DIR)

    def __setattr__(self, name, value):
        raise AttributeError(mtext("api только для чтения", "api is read-only"))

    @property
    def id(self):
        return self._h["id"]

    @property
    def name(self):
        return self._h["rec"]["name"]

    @property
    def version(self):
        return self._h["rec"]["ver"]

    @property
    def lang(self):
        return LANG

    def _need(self, perm):
        if self._mode != "off" and perm not in MODUL_MODE_PERMS[self._mode]:
            raise PermissionError(mtext("нет разрешения: ", "no permission: ") + perm)

    def say(self, text="", color=None):
        col = MODUL_COLORS.get(color, "")
        end = RESET if col else ""
        for line in modul_clean_text(text).split("\n"):
            say(f"{DIM}[{self._h['id']}]{RESET} {col}{line}{end}")

    def t(self, ru="", en=""):
        return str(ru if LANG == "ru" else en)

    def ask(self, prompt=""):
        self._need("ask")
        return modul_ask(f"[{self._h['id']}] {modul_clean_text(prompt)}")

    def command(self, name, func, desc=""):
        self._need("commands")
        modul_add_command(self._h, name, func, desc)

    def on(self, event, func):
        self._need("hooks")
        modul_add_hook(self._h, event, func)

    def last_run(self):
        self._need("read_data")
        return modul_copy_last_run()

    def load(self, default=None):
        self._need("storage")
        return modul_storage_load(self._h["id"], default)

    def save(self, data):
        self._need("storage")
        modul_storage_save(self._h["id"], data)


def modul_add_command(h, name, func, desc):
    if not isinstance(name, str) or not re.fullmatch(r"[a-z][a-z0-9_]{1,19}", name):
        raise ValueError(mtext("имя команды: a-z, 0-9 и _ (2-20 символов)", "command name: a-z, 0-9 and _ (2-20 chars)"))
    if name in MODUL_BUILTIN_CMDS or name in MODUL_COMMANDS:
        raise ValueError(mtext("команда уже занята: ", "command is already taken: ") + name)
    if not callable(func):
        raise ValueError(mtext("вторым аргументом нужна функция", "the 2nd argument must be a function"))
    MODUL_COMMANDS[name] = (h["id"], func)
    h["commands"].append(name)
    if desc:
        row = (name + "  [" + h["id"] + "]", modul_clean_text(desc)[:300])
        for lang in ("ru", "en"):
            MODUL_HELP_ROWS[lang].append(row)
        h["rows"].append(row)


def modul_add_hook(h, event, func):
    if event not in MODUL_EVENTS:
        raise ValueError(mtext("нет такого события, есть: ", "unknown event, available: ") + ", ".join(MODUL_EVENTS))
    if not callable(func):
        raise ValueError(mtext("вторым аргументом нужна функция", "the 2nd argument must be a function"))
    h["hooks"].append((event, func))



def modul_error_text(h, e):
    lineno = None
    tb = e.__traceback__
    while tb is not None:
        if tb.tb_frame.f_code.co_filename == h["rec"]["file"]:
            lineno = tb.tb_lineno
        tb = tb.tb_next
    if lineno is None:
        lineno = getattr(e, "lineno", None)
    where = (mtext(" (строка %d)", " (line %d)") % lineno) if lineno else ""
    return modul_one_line(f"{type(e).__name__}: {e}", 300) + where


def modul_unload(mid):
    h = MODUL_LOADED.pop(mid, None)
    if h is None:
        return
    for name in h["commands"]:
        MODUL_COMMANDS.pop(name, None)
    for row in h["rows"]:
        for lang in ("ru", "en"):
            if row in MODUL_HELP_ROWS[lang]:
                MODUL_HELP_ROWS[lang].remove(row)


def modul_report_error(h, e):
    h["errors"] += 1
    say(f"{RED}[{h['id']}] " + mtext("ошибка", "error") + f": {modul_error_text(h, e)}{RESET}")
    if h["errors"] >= 5:
        modul_unload(h["id"])
        say(f"{YELLOW}[{h['id']}] " + mtext("слишком много ошибок, модуль выгружен до перезапуска скрипта", "too many errors, the module is unloaded until the script restarts") + RESET)


def modul_call(h, func, *args):
    # c116
    try:
        return func(*args)
    except (Exception, KeyboardInterrupt, SystemExit) as e:
        modul_report_error(h, e)
    return None


def modul_load(rec, mode):
    # c117
    mid = rec["id"]
    if mid in MODUL_LOADED:
        return True, ""
    h = {"id": mid, "rec": rec, "mode": mode, "commands": [], "hooks": [], "rows": [], "errors": 0}
    api = ModulAPI(h, mode)
    ns = {"__name__": "modul_" + mid, "api": api}
    if mode != "off":
        ns["__builtins__"] = modul_safe_builtins(api)
    MODUL_LOADED[mid] = h
    try:
        code = compile(modul_strip_header(rec["text"]), rec["file"], "exec", 0, True)
        exec(code, ns)
    except (Exception, KeyboardInterrupt, SystemExit) as e:
        modul_unload(mid)
        return False, modul_error_text(h, e)
    for event, func in list(h["hooks"]):
        if event == "start":
            modul_call(h, func)
    return True, ""


def modul_fire(event, *payload):
    # c118
    if not MODUL_LOADED:
        return
    try:
        if event == "command" and payload and payload[0] == "key":
            payload = ("key", [])
        for mid in list(MODUL_LOADED):
            h = MODUL_LOADED.get(mid)
            if h is None:
                continue
            for ev, func in list(h["hooks"]):
                if ev == event and mid in MODUL_LOADED:
                    modul_call(h, func, *payload)
    except Exception as e:
        say(f"{RED}modul: {type(e).__name__}: {e}{RESET}")


def modul_run_command(cmd, args):
    # c120
    item = MODUL_COMMANDS.get(cmd)
    if item is None:
        return False
    h = MODUL_LOADED.get(item[0])
    if h is not None:
        modul_call(h, item[1], list(args))
    return True



# c122
MODUL_PERMS = {
    "commands": (1, "добавляет свои команды", "adds its own commands"),
    "hooks": (1, "реагирует на события скрипта (start, run_done, command, exit)", "reacts to script events (start, run_done, command, exit)"),
    "ask": (1, "задаёт вопросы в консоли", "asks questions in the console"),
    "read_data": (1, "читает результат последнего run: список модов, версии, стороны", "reads the last run: mods, versions, sides"),
    "storage": (2, "пишет свой файл modul_data/<id>.json (до 64 КБ)", "writes its own file modul_data/<id>.json (up to 64 KB)"),
    "full": (4, "полный доступ: файлы, сеть, процессы, весь код скрипта", "full access: files, network, processes, the whole script"),
}
MODUL_MODE_PERMS = {
    "strict": {"commands", "hooks", "ask", "read_data"},
    "on": {"commands", "hooks", "ask", "read_data", "storage"},
}
MODUL_API_PERM = {
    "command": "commands", "on": "hooks", "ask": "ask", "last_run": "read_data",
    "load": "storage", "save": "storage", "raw": "full", "script_dir": "full",
}

# c125
MODUL_SAFE_MODULES = {
    "re": "compile match fullmatch search sub subn split findall finditer escape IGNORECASE I MULTILINE M DOTALL S VERBOSE X ASCII A error".split(),
    "json": "loads dumps JSONDecodeError".split(),
    "time": "time strftime localtime gmtime monotonic perf_counter".split(),
    "datetime": "date datetime time timedelta timezone".split(),
    "collections": "OrderedDict defaultdict deque namedtuple".split(),
    "functools": "partial reduce lru_cache cmp_to_key wraps".split(),
    "string": "ascii_letters ascii_lowercase ascii_uppercase digits hexdigits punctuation whitespace printable".split(),
    "random": "random randint randrange choice choices shuffle sample uniform seed".split(),
    "textwrap": "wrap fill dedent indent shorten".split(),
    "math": None,
    "itertools": None,
}
MODUL_IMPORT_RISK = {
    "os": 4, "sys": 4, "subprocess": 4, "ctypes": 4, "importlib": 4, "builtins": 4, "pickle": 4,
    "marshal": 4, "multiprocessing": 4, "shutil": 3, "socket": 3, "urllib": 3, "http": 3,
    "requests": 3, "ftplib": 3, "smtplib": 3, "pathlib": 3, "glob": 3, "tempfile": 3,
    "zipfile": 3, "threading": 3, "signal": 3,
}
# c127
MODUL_BAD_NAMES = {
    "eval": 4, "exec": 4, "compile": 4, "__import__": 4, "getattr": 4, "setattr": 4, "delattr": 4,
    "globals": 4, "locals": 4, "vars": 4, "type": 4, "object": 4, "memoryview": 4, "breakpoint": 4,
    "open": 3, "input": 2, "exit": 2, "quit": 2, "help": 2,
}
MODUL_BAD_ATTRS = set((
    "gi_frame gi_code gi_yieldfrom cr_frame cr_code cr_await ag_frame ag_code "
    "f_back f_globals f_locals f_builtins f_code tb_frame tb_next co_code mro"
).split())
MODUL_SAFE_BUILTINS = (
    "abs all any ascii bin bool bytes callable chr classmethod dict divmod enumerate filter float "
    "format frozenset hash hex int isinstance issubclass iter len list map max min next oct ord pow "
    "property range repr reversed round set slice sorted staticmethod str sum super tuple zip "
    "Exception ValueError TypeError KeyError IndexError RuntimeError StopIteration "
    "ZeroDivisionError NotImplementedError AttributeError NotImplemented Ellipsis"
).split()

def modul_safe_builtins(api):
    # c129
    b = {}
    for name in MODUL_SAFE_BUILTINS:
        b[name] = getattr(builtins, name)
    proxies = {}

    def safe_import(name, globals=None, locals=None, fromlist=(), level=0):
        if level or name not in MODUL_SAFE_MODULES:
            raise ImportError(mtext("импорт запрещён: ", "import is not allowed: ") + str(name))
        if name not in proxies:
            real = __import__(name)
            names = MODUL_SAFE_MODULES[name]
            if names is None:
                names = [n for n in dir(real) if not n.startswith("_")]
            proxies[name] = types.SimpleNamespace(**{n: getattr(real, n) for n in names if hasattr(real, n)})
        return proxies[name]

    def safe_print(*items, sep=" ", **_ignored):
        api.say(str(sep).join(str(x) for x in items))

    b["print"] = safe_print
    b["__import__"] = safe_import
    b["__build_class__"] = builtins.__build_class__
    return b


def modul_check_import(name, line, bad):
    if name in MODUL_SAFE_MODULES:
        return
    risk = MODUL_IMPORT_RISK.get(name.split(".")[0], 2)
    bad.append((line, risk, mtext("импорт ", "import ") + name))


def modul_scan_code(text):
    # c131
    info = {"problems": [], "perms": set(), "adds": [], "syntax": ""}
    try:
        tree = ast.parse(modul_strip_header(text))
    except SyntaxError as e:
        info["syntax"] = f"{e.msg} ({mtext('строка', 'line')} {e.lineno})"
        return info
    except (ValueError, RecursionError, MemoryError):
        info["syntax"] = mtext("код не удалось разобрать", "cannot parse the code")
        return info
    bad = info["problems"]
    no_word = mtext("нельзя использовать ", "not allowed: ")
    for node in ast.walk(tree):
        line = getattr(node, "lineno", 0)
        if isinstance(node, ast.Import):
            for alias in node.names:
                modul_check_import(alias.name, line, bad)
        elif isinstance(node, ast.ImportFrom):
            if node.level or not node.module:
                bad.append((line, 4, mtext("относительный импорт", "relative import")))
            else:
                modul_check_import(node.module, line, bad)
            if any(a.name == "*" for a in node.names):
                bad.append((line, 3, "import *"))
        elif type(node).__name__ == "Match":
            bad.append((line, 3, mtext("нельзя match/case", "no match/case")))
        elif isinstance(node, ast.Name):
            if node.id in MODUL_BAD_NAMES:
                bad.append((line, MODUL_BAD_NAMES[node.id], no_word + node.id))
            elif node.id.startswith("__"):
                bad.append((line, 4, no_word + node.id))
        elif isinstance(node, ast.Attribute):
            attr = node.attr
            if attr in ("format", "format_map"):
                bad.append((line, 2, mtext('нельзя .format (используй f-строку)', "do not use .format (use an f-string)")))
            elif attr in MODUL_BAD_ATTRS or (attr.startswith("_") and not (attr == "__init__" and isinstance(node.ctx, ast.Load))):
                bad.append((line, 4, no_word + "." + attr))
            base = node.value
            if isinstance(base, ast.Name) and base.id == "api" and attr in MODUL_API_PERM:
                info["perms"].add(MODUL_API_PERM[attr])
        elif isinstance(node, ast.Call):
            f = node.func
            if isinstance(f, ast.Attribute) and isinstance(f.value, ast.Name) and f.value.id == "api" and f.attr in ("command", "on"):
                first = node.args[0] if node.args else None
                if isinstance(first, ast.Constant) and isinstance(first.value, str):
                    info["adds"].append((f.attr, first.value))
                else:
                    info["adds"].append((f.attr, "?"))
    bad.sort()
    return info


def modul_evaluate(rec, mode):
    # c133
    info = modul_scan_code(rec["text"])
    perms = set(info["perms"])
    risk = 1
    for p in perms:
        risk = max(risk, MODUL_PERMS[p][0])
    for _line, r, _text in info["problems"]:
        risk = max(risk, r)
    why = []
    if info["syntax"]:
        why.append(mtext("ошибка в коде: ", "code error: ") + info["syntax"])
    elif mode != "off":
        if info["problems"]:
            why.append(mtext("в коде есть запрещённое в этом режиме (см. список), нужен режим off", "the code uses things that are blocked in this mode (see the list), off mode is needed"))
        lack = sorted(p for p in perms if p not in MODUL_MODE_PERMS[mode])
        if lack:
            why.append(mtext("нужны разрешения, которых нет в режиме ", "needs permissions missing in mode ") + mode + ": " + ", ".join(lack))
    return info, perms, risk, why



MODUL_HELP_ROWS = {
    "ru": [
        ("modul", 'Модули-дополнения: файлы .py/.txt рядом со скриптом с шапкой idname/idmodul/iddescription/idversion. Меню: список, вкл/выкл (безопасные модули включаются сразу, для опасных - сеть, файлы, программы - показывается предупреждение и вводится id), подробности, security, мануал.'),
        ("modul security strict|on|off", 'Режим защиты модулей. strict и on ограничивают модуль и не дают ему менять этот режим, off - без защиты. modul help - мануал.'),
        ("modul unprotect|protect <id>", 'Разрешить одному модулю работать без защиты (или вернуть защиту). Остальные остаются под общим режимом security. Разрешение действует, пока файл модуля не менялся. В меню: u N.'),
    ],
    "en": [
        ("modul", 'Add-on modules: .py/.txt files next to the script with a header containing idname/idmodul/iddescription/idversion. Menu: list, on/off (safe modules are enabled immediately; dangerous ones—network, files, programs—show a warning and require the module ID), details, security, manual.'),
        ("modul security strict|on|off", 'Module protection mode. strict and on restrict modules and prevent them from changing this mode; off disables protection. modul help - manual.'),
        ("modul unprotect|protect <id>", 'Allow one module to run without protection (or restore protection). Other modules remain under the global security mode. The permission remains valid until the module file is changed. In the menu: u N.'),
    ],
}
HELP_GROUPS["ru"].insert(len(HELP_GROUPS["ru"]) - 1, ("Модули", MODUL_HELP_ROWS["ru"]))
HELP_GROUPS["en"].insert(len(HELP_GROUPS["en"]) - 1, ("Modules", MODUL_HELP_ROWS["en"]))
for _lang, _word in (("ru", "help (все команды"), ("en", "help (all commands")):
    T[_lang]["commands"] = T[_lang]["commands"].replace(_word, "modul | " + _word, 1)

MODUL_RISK_NAMES = {
    1: ("низкий", "low", GREEN),
    2: ("средний", "medium", YELLOW),
    3: ("высокий", "high", RED),
    4: ("КРИТИЧЕСКИЙ", "CRITICAL", RED + BOLD),
}
MODUL_DISCLAIMER = {
    "ru": (
        'Модуль это дополнение интеграция для скрипта расширяющяя возможности.',
        'Без защиты (режим off) она может удалять и менять любые файлы, читать твои данные, ходить в сеть,',
        'скачивать, устанавливать и запускать другие программы.',
        'Включайте только модули, код которых вы прочитали, или автору которых доверяешь.',
        'Сомневаетесь не включайте: проверь файл через нейронку или покажите код тому, кто разбирается.',
    ),
    "en": (
        'A module is an add-on/integration for the script that expands its capabilities.',
        'Without protection (off mode), it can delete and modify any files, read your data, and access the network,',
        'download, install, and run other programs.',
        'Enable only modules whose code you have read or whose author you trust.',
        'If you are unsure, do not enable it: scan the file with an AI assistant or show the code to someone knowledgeable.',
    ),
}
MODUL_MODE_TEXT = {
    "ru": (
        'strict - строгий: модуль только добавляет команды, слушает события, задаёт вопросы и читает результат run. Ничего не пишет.',
        'on     - как strict, плюс свой файл данных modul_data/<id>.json. Файлов, сети и процессов нет.',
        'off    - защиты нет: модуль делает что хочет (файлы, сеть, процессы, весь код скрипта). Может быть опасно.',
        'В strict и on модуль не может поменять этот режим.',
        'Отдельному модулю можно разрешить работать без защиты: modul unprotect <id>. У остальных остаётся общий режим.',
        'Безопасные модули (только команды, без сети, файлов и установки чего-либо) включаются без вопросов, опасные - после предупреждения и ввода id модуля. Без защиты (off) опасным считается и любой import.',
        'Настоящей песочницы в Python нет: strict и on снижают риск ошибок и простых вредных модулей, но от намеренно хитрого кода гарантии не дают.',
    ),
    "en": (
        'strict - strict mode: a module can only add commands, listen to events, ask questions, and read the result of run. It writes nothing.',
        "on     - like strict, plus its own data file modul_data/<id>.json. No access to other files, the network or processes.",
        "off    - no protection: a module can do anything (files, network, processes, the entire script). This may be dangerous.",
        "In strict and on modes, a module cannot change its protection mode.",
        "A single module can be allowed to run without protection: modul unprotect <id>. The others keep the global mode.",
        "Safe modules (only commands, no network, files or installing anything) are enabled without questions, dangerous ones after a warning and typing the module id. Without protection (off) any import counts as dangerous too.",
        "Python has no true sandbox. The strict and on modes reduce the risk from mistakes and simple malicious modules, but cannot guarantee protection against deliberately evasive code.",
    ),
}


def modul_risk_label(risk):
    ru, en, color = MODUL_RISK_NAMES[risk]
    return color + mtext(ru, en) + RESET


def modul_disclaimer(caps=None):
    say()
    if caps:
        say(RED + BOLD + mtext("ВНИМАНИЕ: модуль потенциально опасный, он может: ", "WARNING: the module is dangerous, it can: ") + "; ".join(modul_cap_texts(caps)) + RESET)
    else:
        say(RED + BOLD + mtext('ВНИМАНИЕ: МОДУЛИ ЭТО ЧУЖОЙ КОД', 'WARNING: MODULES ARE THIRD-PARTY CODE') + RESET)
    for line in MODUL_DISCLAIMER["ru" if LANG == "ru" else "en"]:
        say(line)


def modul_show_manual():
    try:
        with open(MODUL_MANUAL_PATH, "r", encoding="utf-8") as f:
            text = f.read()
    except OSError:
        say(mtext("MODUL_MANUAL.txt не найден рядом со скриптом.",
                  "MODUL_MANUAL.txt not found next to the script. Run the patcher again, it creates the manual."))
        return
    ru, _sep, en = text.partition("\n===== ENGLISH =====\n")
    say(ru if (LANG == "ru" or not en) else en)



def modul_show_list(recs):
    mode = MODUL_STATE["security"]
    say()
    say(GREEN + BOLD + mtext("=== Модули ===", "=== Modules ===") + RESET + "  security: " + BOLD + mode + RESET)
    if not recs:
        say(mtext('Модулей нет. Положите файл .py или .txt с шапкой (idname= idmodul= iddescription= idversion=) в папку со скриптом. Подробнее: modul help',
                  'No modules found. Put a .py or .txt file with the header (idname= idmodul= iddescription= idversion=) in the script folder. See modul help.'))
        return
    for i, rec in enumerate(recs, 1):
        if rec["error"]:
            say(f"{i:>2}. {RED}[" + mtext("ошибка", "error") + f"]{RESET} {rec['file']}: {rec['error']}")
            continue
        rec_mode = modul_mode_for(rec)
        _info, _perms, risk, why = modul_evaluate(rec, rec_mode)
        enabled = rec["id"] in MODUL_STATE["enabled"]
        if rec["id"] in MODUL_LOADED:
            state = GREEN + "[" + mtext("ВКЛ", "ON") + "]" + RESET
        elif enabled:
            state = YELLOW + "[" + mtext("ВКЛ, не загружен", "ON, not loaded") + "]" + RESET
        else:
            state = DIM + "[" + mtext("выкл", "off") + "]" + RESET
        own_off = rec_mode == "off" and mode != "off"
        flag = (" " + RED + BOLD + "[" + mtext("БЕЗ ЗАЩИТЫ", "UNPROTECTED") + "]" + RESET) if own_off else ""
        say(f"{i:>2}. {state} {BOLD}{rec['name']}{RESET} v{rec['ver']} ({rec['id']})  " + mtext("риск: ", "risk: ") + modul_risk_label(risk) + flag)
        say("      " + rec["desc"])
        if enabled and rec["id"] not in MODUL_LOADED and rec["id"] in MODUL_NOTES:
            say("      " + YELLOW + MODUL_NOTES[rec["id"]] + RESET)
        elif why and not enabled:
            say("      " + DIM + mtext("в режиме ", "cannot be enabled in mode ") + rec_mode + mtext(" включить нельзя", "") + RESET)
        if modul_grant_stale(rec):
            say("      " + YELLOW + mtext("разрешение работать без защиты снято: файл изменился", "permission to run unprotected was dropped: the file changed") + RESET)


def modul_show_info(rec):
    mode = modul_mode_for(rec)
    info, perms, risk, why = modul_evaluate(rec, mode)
    say()
    say(f"{GREEN}{BOLD}=== {rec['name']}  v{rec['ver']}  [{rec['id']}] ==={RESET}")
    say(mtext("Описание: ", "Description: ") + rec["desc"])
    say(mtext("Файл: ", "File: ") + f"{rec['file']}, {rec['size']} B, sha256 {rec['sha'][:12]}")
    own_off = mode == "off" and MODUL_STATE["security"] != "off"
    note = ""
    if own_off:
        note = RED + mtext("  (личное разрешение этому модулю, общий режим: ", "  (personal permission for this module, global mode: ") + MODUL_STATE["security"] + ")" + RESET
    say(mtext("Режим защиты: ", "Security mode: ") + mode + note)
    say()
    say(BOLD + mtext("Что добавляет или меняет:", "What it adds or changes:") + RESET)
    for kind, value in info["adds"]:
        if kind == "command":
            say("  + " + mtext("команда ", "command ") + value)
        else:
            say("  + " + mtext("реакция на событие ", "reaction to event ") + value)
    caps = modul_danger(rec, perms, mode)
    if caps:
        say("  ! " + mtext("может: ", "can: ") + "; ".join(modul_cap_texts(caps)))
    elif not info["adds"]:
        say("  " + mtext("ничего не регистрирует, только выполняет свой код при загрузке", "registers nothing, only runs its code on load"))
    say(BOLD + mtext("Разрешения (по разбору кода):", "Permissions (from the code scan):") + RESET)
    if not perms:
        say("  " + mtext("только вывод текста", "only text output"))
    for p in sorted(perms):
        r, ru, en = MODUL_PERMS[p]
        say(f"  {p} [{modul_risk_label(r)}] - " + mtext(ru, en))
    declared = set(rec["declared"])
    if not declared:
        say(DIM + mtext("Автор не указал idperms", "The author did not set idperms") + RESET)
    else:
        say(mtext("Заявлено автором (idperms): ", "Declared by the author (idperms): ") + ", ".join(sorted(declared)))
        extra = sorted(perms - declared)
        if extra:
            say(YELLOW + mtext("Автор НЕ заявил, но код использует: ", "NOT declared by the author, but the code uses: ") + ", ".join(extra) + RESET)
    if info["problems"]:
        say(BOLD + mtext("Запрещено в strict/on, работает только в off:", "Blocked in strict/on, works only in off:") + RESET)
        for line, r, text in info["problems"][:10]:
            say(f"  {mtext('строка', 'line')} {line}: {text} [{modul_risk_label(r)}]")
        if len(info["problems"]) > 10:
            say("  ...")
    say(BOLD + mtext("Общий риск: ", "Overall risk: ") + RESET + modul_risk_label(risk))
    if own_off:
        say(DIM + mtext("Вернуть защиту только этому модулю: modul protect ", "Restore protection for this module only: modul protect ") + rec["id"] + mtext(" (в меню: u N)", " (in the menu: u N)") + RESET)
    elif why and mode != "off" and not info["syntax"]:
        say(DIM + mtext("Разрешить только этому модулю работать без защиты (у остальных она останется): modul unprotect ",
                        "Let only this module run without protection (the others keep it): modul unprotect ") + rec["id"] + mtext(" (в меню: u N)", " (in the menu: u N)") + RESET)
    return perms, risk, why



def modul_enable_flow(rec):
    mode = modul_mode_for(rec)
    _info, perms, _risk, why = modul_evaluate(rec, mode)
    caps = [] if why else modul_danger(rec, perms, mode)
    if why or caps:
        modul_show_info(rec)
        say()
    if why:
        say(RED + mtext("Включить нельзя: ", "Cannot enable: ") + RESET + "; ".join(why))
        return
    if caps and not modul_confirm_danger(rec, caps):
        return
    ok, err = modul_load(rec, mode)
    if not ok:
        say(RED + mtext("Ошибка при запуске модуля: ", "Error while starting the module: ") + err + RESET)
        return
    MODUL_STATE["enabled"][rec["id"]] = {"sha": rec["sha"], "mode": mode, "perms": sorted(perms)}
    MODUL_NOTES.pop(rec["id"], None)
    modul_save_state()
    say(GREEN + mtext("Модуль включён: ", "Module enabled: ") + rec["id"] + RESET)
    h = MODUL_LOADED.get(rec["id"])
    if h and h["commands"]:
        say(mtext("Добавлены команды: ", "Commands added: ") + ", ".join(h["commands"]))


def modul_disable(rec):
    h = MODUL_LOADED.get(rec["id"])
    modul_unload(rec["id"])
    MODUL_STATE["enabled"].pop(rec["id"], None)
    MODUL_NOTES.pop(rec["id"], None)
    modul_save_state()
    say(GREEN + mtext("Модуль выключен: ", "Module disabled: ") + rec["id"] + RESET)
    if h and h["mode"] == "off":
        say(YELLOW + mtext('Модуль работал без защиты. Перезапустите скрипт, чтобы убрать всё, что он успел изменить по части кода скрипта.',
                           'The module ran without protection. Restart the script to undo any changes it made to the script code.') + RESET)


def modul_toggle(rec):
    if rec["error"]:
        say(rec["error"])
    elif rec["id"] in MODUL_STATE["enabled"]:
        modul_disable(rec)
    else:
        modul_enable_flow(rec)


def modul_load_enabled():
    # c141
    recs = {r["id"]: r for r in modul_scan() if not r["error"]}
    loaded = 0
    for mid in list(MODUL_STATE["enabled"]):
        rec = recs.get(mid)
        why = ""
        if rec is None:
            why = mtext("файл модуля не найден", "module file not found")
        elif rec["sha"] != MODUL_STATE["enabled"][mid].get("sha"):
            why = mtext('файл изменился после включения, включи заново через modul', 'the file changed after it was enabled; enable it again using modul')
        else:
            rec_mode = modul_mode_for(rec)
            _info, _perms, _risk, bad = modul_evaluate(rec, rec_mode)
            if bad:
                why = "; ".join(bad)
            else:
                ok, err = modul_load(rec, rec_mode)
                if ok:
                    loaded += 1
                else:
                    why = err
        if why:
            MODUL_NOTES[mid] = why
            say(f"{YELLOW}[modul] {mid}: {why}{RESET}")
    return loaded


def modul_start():
    try:
        modul_load_state()
        if MODUL_STATE["enabled"]:
            n = modul_load_enabled()
            say(f"{DIM}[modul] " + mtext("загружено модулей: ", "modules loaded: ") + f"{n}, security: {MODUL_STATE['security']}{RESET}")
    except Exception as e:
        say(f"{RED}modul: {type(e).__name__}: {e}{RESET}")


# c143

def modul_security_cmd(args):
    cur = MODUL_STATE["security"]
    if not args or args[0] not in MODUL_MODES:
        say("security: " + BOLD + cur + RESET)
        for line in MODUL_MODE_TEXT["ru" if LANG == "ru" else "en"]:
            say("  " + line)
        say(mtext("Сменить: modul security strict | on | off", "Change: modul security strict | on | off"))
        return
    new = args[0]
    if new == cur:
        say(mtext("Уже стоит режим ", "Already set: ") + cur)
        return
    if new == "off":
        modul_disclaimer()
        if modul_ask(mtext('Чтобы включить off, введи OFF заглавными: ', 'To enable off mode, enter OFF in uppercase: ')) != "OFF":
            say(mtext("Отменено.", "Cancelled."))
            return
    MODUL_STATE["security"] = new
    modul_save_state()
    say(GREEN + "security: " + new + RESET)
    for mid in list(MODUL_LOADED):
        h = MODUL_LOADED.get(mid)
        if h is not None and h["mode"] == "off" and mid in MODUL_STATE["unprotected"]:
            continue
        modul_unload(mid)
    modul_load_enabled()
    if cur == "off":
        say(YELLOW + mtext('Ранее модули работали без защиты. Перезапустите скрипт, чтобы убрать всё, что они успели изменить по части кода скрипта.',
                           'Modules previously ran without protection. Restart the script to undo any changes they made to the script code.') + RESET)



def modul_grant_stale(rec):
    grant = MODUL_STATE.get("unprotected", {}).get(rec["id"])
    return bool(grant) and grant.get("sha") != rec.get("sha")


def modul_mode_for(rec):
    # c148
    grant = MODUL_STATE.get("unprotected", {}).get(rec["id"])
    if grant and rec.get("sha") and grant.get("sha") == rec["sha"]:
        return "off"
    return MODUL_STATE["security"]


def modul_apply_mode(rec):
    mid = rec["id"]
    entry = MODUL_STATE["enabled"].get(mid)
    if entry is None:
        return
    mode = modul_mode_for(rec)
    h = MODUL_LOADED.get(mid)
    if h is not None and h["mode"] == mode and h["rec"]["sha"] == rec["sha"]:
        return
    modul_unload(mid)
    MODUL_NOTES.pop(mid, None)
    if entry.get("sha") != rec["sha"]:
        why = mtext('файл изменился после включения, включи заново через modul', 'the file changed after it was enabled; enable it again using modul')
    else:
        _info, _perms, _risk, bad = modul_evaluate(rec, mode)
        if bad:
            why = "; ".join(bad)
        else:
            ok, err = modul_load(rec, mode)
            why = "" if ok else err
    if why:
        MODUL_NOTES[mid] = why
        say(f"{YELLOW}[modul] {mid}: {why}{RESET}")
    else:
        say(GREEN + mtext("Модуль перезапущен: ", "Module restarted: ") + mid + ", security: " + mode + RESET)


def modul_unprotect_flow(rec):
    if rec["error"]:
        say(rec["error"])
        return
    if MODUL_STATE["security"] == "off":
        say(mtext("Общий режим уже off, защиты нет ни у одного модуля.", "The global mode is already off, no module is protected."))
        return
    if modul_mode_for(rec) == "off":
        say(mtext("Этому модулю уже разрешено работать без защиты.", "This module is already allowed to run unprotected."))
        return
    enabled = rec["id"] in MODUL_STATE["enabled"]
    if enabled:
        _info, perms, _risk, why = modul_evaluate(rec, "off")
        if why:
            say(RED + mtext("Нельзя: ", "Cannot: ") + RESET + "; ".join(why))
            return
        caps = modul_danger(rec, perms, "off")
        if caps:
            modul_show_info(rec)
            say()
            if not modul_confirm_danger(rec, caps):
                return
    MODUL_STATE.setdefault("unprotected", {})[rec["id"]] = {"sha": rec["sha"], "time": datetime.datetime.now().strftime("%Y-%m-%d %H:%M")}
    modul_save_state()
    say(GREEN + mtext("Модулю разрешено работать без защиты: ", "The module may run without protection: ") + rec["id"] + RESET)
    if enabled:
        modul_apply_mode(rec)
    else:
        say(mtext('Модуль пока выключен. Включите его через modul (номер): если он опасный, предупреждение и ввод id будут там.',
                  'The module is still disabled. Enable it through modul (its number); if it is dangerous, the warning and ID prompt will appear there.'))


def modul_protect(rec):
    # c152
    if MODUL_STATE.setdefault("unprotected", {}).pop(rec["id"], None) is None:
        say(mtext("У этого модуля нет личного разрешения работать без защиты.", "This module has no personal permission to run unprotected."))
        return
    modul_save_state()
    say(GREEN + mtext("Защита модулю возвращена: ", "Protection restored for the module: ") + rec["id"] + ", security: " + MODUL_STATE["security"] + RESET)
    h = MODUL_LOADED.get(rec["id"])
    was_off = bool(h and h["mode"] == "off")
    modul_apply_mode(rec)
    if was_off and MODUL_STATE["security"] != "off":
        say(YELLOW + mtext('Модуль работал без защиты. Перезапустите скрипт, чтобы убрать всё, что он успел изменить по части кода скрипта.',
                           'The module ran without protection. Restart the script to undo any changes it made to the script code.') + RESET)


def modul_unprotect_toggle(rec):
    if rec["error"]:
        say(rec["error"])
    elif rec["id"] in MODUL_STATE.get("unprotected", {}):
        modul_protect(rec)
    else:
        modul_unprotect_flow(rec)


# c153

MODUL_CAP_ORDER = ("network", "process", "files", "other", "code")
MODUL_CAP_TEXT = {
    "network": ("выходить в сеть", "use the network"),
    "process": ("запускать программы и устанавливать пакеты", "run programs and install packages"),
    "files": ("читать и менять файлы", "read and change files"),
    "other": ("подключать системные модули Python", "import Python system modules"),
    "code": ("выполнять любой код и менять сам скрипт", "run any code and change the script itself"),
}

MODUL_CAP_BY_ROOT = {
    "socket": ("network",), "urllib": ("network",), "urllib3": ("network",), "http": ("network",), "requests": ("network",),
    "ftplib": ("network",), "smtplib": ("network",), "ssl": ("network",), "asyncio": ("network",), "aiohttp": ("network",),
    "httpx": ("network",), "websocket": ("network",), "websockets": ("network",), "xmlrpc": ("network",),
    "telnetlib": ("network",), "poplib": ("network",), "imaplib": ("network",), "socketserver": ("network",),
    "webbrowser": ("network",),
    "subprocess": ("process",), "multiprocessing": ("process",), "pip": ("process",), "ensurepip": ("process",),
    "venv": ("process",), "setuptools": ("process",), "distutils": ("process",), "pty": ("process",),
    "os": ("process", "files"),
    "shutil": ("files",), "pathlib": ("files",), "glob": ("files",), "tempfile": ("files",), "zipfile": ("files",),
    "tarfile": ("files",), "gzip": ("files",), "bz2": ("files",), "lzma": ("files",), "sqlite3": ("files",),
    "dbm": ("files",), "shelve": ("files",), "fileinput": ("files",), "io": ("files",), "logging": ("files",),
    "ctypes": ("code",), "importlib": ("code",), "builtins": ("code",), "pickle": ("code",), "marshal": ("code",),
    "runpy": ("code",), "code": ("code",), "codeop": ("code",), "pkgutil": ("code",), "sys": ("code",),
    "inspect": ("code",), "gc": ("code",),
}

MODUL_CODE_NAMES = {"eval", "exec", "compile", "__import__", "getattr", "setattr", "delattr", "globals", "locals", "vars", "breakpoint",
                    "help",
                    "exit", "quit"}

def modul_cap_texts(caps):
    i = 0 if LANG == "ru" else 1
    return [MODUL_CAP_TEXT[c][i] for c in caps]


def modul_capabilities(text, real=False):
    found = set()
    try:
        tree = ast.parse(modul_strip_header(text))
    except (SyntaxError, ValueError, RecursionError, MemoryError):
        return []
    for node in ast.walk(tree):
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            if isinstance(node, ast.Import):
                names = [a.name for a in node.names]
            else:
                names = [node.module or ""]
                if node.level or not node.module:
                    found.add("code")
            if real:
                found.add("other")
            for name in names:
                if name and name not in MODUL_SAFE_MODULES:
                    found.update(MODUL_CAP_BY_ROOT.get(name.split(".")[0], ("other",)))
        elif isinstance(node, ast.Name):
            if node.id == "open":
                found.add("files")
            elif node.id in MODUL_CODE_NAMES or node.id.startswith("__"):
                found.add("code")
        elif isinstance(node, ast.Attribute):
            attr = node.attr
            if attr in MODUL_BAD_ATTRS or (attr.startswith("_") and not (attr == "__init__" and isinstance(node.ctx, ast.Load))):
                found.add("code")
            base = node.value
            if isinstance(base, ast.Name) and base.id == "api" and MODUL_API_PERM.get(attr) == "full":
                found.add("code")
    return [c for c in MODUL_CAP_ORDER if c in found]


def modul_danger(rec, perms, mode):
    caps = modul_capabilities(rec["text"], real=(mode == "off"))
    if "full" in perms and "code" not in caps:
        caps = [c for c in MODUL_CAP_ORDER if c in set(caps) | {"code"}]
    return caps


def modul_confirm_danger(rec, caps):
    modul_disclaimer(caps)
    if modul_ask(mtext('Чтобы включить, введи id модуля: ', 'To enable it, enter the module ID: ')) != rec["id"]:
        say(mtext("Отменено.", "Cancelled."))
        return False
    return True


def modul_menu():
    while True:
        recs = modul_scan()
        modul_show_list(recs)
        say(mtext('Номер - вкл/выкл | i N - подробности | u N - без защиты вкл/выкл | s - security | h - мануал | d - дисклеймер | q - выход',
                  'Number - on/off | i N - details | u N - toggle unprotected mode | s - security | h - manual | d - disclaimer | q - quit'))
        answer = modul_ask("modul> ")
        low = answer.lower()
        if low in ("", "q", "exit"):
            return
        elif low in ("h", "help"):
            modul_show_manual()
        elif low in ("d", "disclaimer"):
            modul_disclaimer()
        elif low in ("s", "security") or low.startswith("s "):
            modul_security_cmd(low.split()[1:])
        elif low.startswith("i "):
            rec = modul_pick(low[2:], recs)
            if rec is None or rec["error"]:
                say(mtext("Нет такого модуля.", "No such module."))
            else:
                modul_show_info(rec)
        elif low.startswith("u "):
            rec = modul_pick(low[2:], recs)
            if rec is None or rec["error"]:
                say(mtext("Нет такого модуля.", "No such module."))
            else:
                modul_unprotect_toggle(rec)
        else:
            rec = modul_pick(answer, recs)
            if rec is None:
                say(mtext("Нет такого модуля.", "No such module."))
            else:
                modul_toggle(rec)


def do_modul(args):
    if not args:
        modul_menu()
    elif args[0] == "security":
        modul_security_cmd(args[1:])
    elif args[0] in ("help", "manual"):
        modul_show_manual()
    elif args[0] == "list":
        modul_show_list(modul_scan())
    elif args[0] in ("unprotect", "protect"):
        if len(args) < 2:
            say(mtext("Использование: modul %s <id или номер>", "Usage: modul %s <id or number>") % args[0])
        else:
            rec = modul_pick(args[1], modul_scan())
            if rec is None or rec["error"]:
                say(mtext("Нет такого модуля.", "No such module."))
            elif args[0] == "unprotect":
                modul_unprotect_flow(rec)
            else:
                modul_protect(rec)
    else:
        say(mtext("Использование: modul | modul list | modul security strict|on|off | modul unprotect|protect <id> | modul help",
                  "Usage: modul | modul list | modul security strict|on|off | modul unprotect|protect <id> | modul help"))


def log_command_crash(cmd, exc):
    import traceback
    say(RED + mtext("Команда ", "Command ") + str(cmd) + mtext(' Ошибка: ', ' Error: ') + f"{type(exc).__name__}: {exc}" + RESET)
    try:
        os.makedirs(LOGS_DIR, exist_ok=True)
        path = os.path.join(LOGS_DIR, "errors.log")
        if os.path.exists(path) and os.path.getsize(path) > 512 * 1024:
            os.replace(path, path + ".old")
        with open(path, "a", encoding="utf-8") as f:
            f.write(f"[{datetime.datetime.now():%Y-%m-%d %H:%M:%S}] {cmd}\n{traceback.format_exc()}\n")
        say(DIM + mtext("Подробности: ", "Details: ") + os.path.join(os.path.basename(LOGS_DIR), "errors.log") + RESET)
    except OSError:
        pass



_AUTO_FINDER_SOURCE = r'''
import os, sys, re, json, time
import threading
import shutil
import urllib.request, urllib.parse, urllib.error
import concurrent.futures
import datetime
import hashlib
import zipfile
import difflib
import shlex
import calendar
import traceback
import random
import glob
__author__ = "A Simple Block"
__license__ = "LicenseRef-Source-Available-Noncommercial-1.0"
__build__ = "af26-mu62ku"

RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"  #F4
BOLD = "\033[1m"  #F7
RESET = "\033[0m"

CACHE_TTL_SECONDS = 7 * 24 * 3600
CATEGORY_TTL_SECONDS = 30 * 24 * 3600
HTTP_TIMEOUT = 15
HTTP_RETRIES = 5
USER_AGENT = "auto-modpacker"

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
OUTPUT_DIR = os.path.join(SCRIPT_DIR, "found_mods")
CF_KEY_PATH = os.path.join(SCRIPT_DIR, "CurseForgeApiKey_DO_NOT_SHARE.txt")
CF_KEY_HEADER = "# Ключ CurseForge API — конфиденциальные данные. Не передавайте этот файл другим лицам.\n"

DEP_TYPE_LABEL = {
    "required": {"ru": 'Обязательные зависимости', "en": "Required dependencies"},
    "optional": {"ru": 'Опциональные зависимости', "en": "Optional dependencies"},
    "incompatible": {"ru": 'Несовместимо с', "en": "Incompatible with"},
    "embedded": {"ru": 'Встроено JAR in JAR (встроенный в мод мод)', "en": "Embedded in another mod (Jar-in-Jar), not a separate mod"},
}
CF_RELATION_TYPE = {3: "required", 2: "optional", 5: "incompatible", 1: "embedded", 6: "embedded", 4: "embedded"}  #F5
CF_CLASS_ID_MODS = 6
MR_PROJECT_TYPE_MOD = "mod"


TOP_PAGES = 8   #F2
PAGE_SIZE = 50
ADDON_SEARCH_LIMIT = 30
DESC_DIFF_MIN = 10
HTTP_WORKERS = 8
NAME_PAGES = 2
NAME_SEARCH_LIMIT = 20
NAME_MATCH_DESC = False   #F9

ALL_MODS_PATH = os.path.join(OUTPUT_DIR, "mods.txt")
AI_MODS_PATH = os.path.join(OUTPUT_DIR, "mods_ai.txt") #F10 I HATE IA USE IF THIS IS NOT FOR ROUTINE I mean things like testing aghhhhh gI hope you understand what I mean
STORE_PATH = os.path.join(OUTPUT_DIR, ".mods_store.json")
RUN_LOG_PATH = os.path.join(OUTPUT_DIR, "run_log.txt")
RUN_LOG_TAIL = 10

MR_ENV_CLIENT = ["client_only", "client_only_server_optional", "client_and_server",
                 "client_or_server", "client_or_server_prefers_both", "singleplayer_only"]
MR_ENV_SERVER = ["server_only", "dedicated_server_only", "server_only_client_optional",
                 "client_and_server", "client_or_server", "client_or_server_prefers_both",
                 "client_only_server_optional"]

CF_MODLOADER_NAME = {1: "Forge", 2: "Cauldron", 3: "LiteLoader", 4: "Fabric", 5: "Quilt", 6: "NeoForge"}
MR_LOADER_LABEL = {"fabric": "Fabric", "forge": "Forge", "quilt": "Quilt", "neoforge": "NeoForge",
                    "liteloader": "LiteLoader", "rift": "Rift"}
LOADER_ORDER = ["Forge", "Fabric", "NeoForge", "Quilt", "Cauldron", "LiteLoader"]
assert set(CF_RELATION_TYPE.values()) == set(DEP_TYPE_LABEL), "dependency kinds out of sync (E8322)"
assert all(n in CF_MODLOADER_NAME.values() for n in LOADER_ORDER), "loader table drift (E3534)"

T = {
    "ru": {
        "lang_prompt": "Выберите язык / Choose language [ru/en]: ",
        "banner_title": "  Auto-Modpacker by A Simple Block",
        "banner_note": 'Ищет моды на Modrinth и CurseForge. Команда bulk берёт верх категории и аддоны к найденным модам, всё пишется в found_mods/mods.txt (для чтения) и found_mods/mods_ai.txt (сжатый вариант для нейронки, меньше токенов).',
        "commands": ('Команды: key <ключ> | search <тег|name:название|ссылка ...> | show <N> | save <N> | saveall | bulk <тег|name:название|ссылка ...> | addons <slug|modid> | build <ссылка|slug ...> | importlink | update | newaddons | help | exit'),
        "key_set": 'Ключ CurseForge сохранён рядом со скриптом.',
        "key_usage": 'Использование: key <ключ>',
        "no_internet": 'Нет интернета, поиск невозможен.',
        "net_mr_down": 'Modrinth не отвечает, работа только с CurseForge.',
        "net_cf_down": 'CurseForge не отвечает, работа только с Modrinth.',
        "auth_error": 'API вернул ошибку авторизации (401/403), ключ CurseForge, не принят.',
        "search_usage": 'Использование: search <тег1|ссылка|name:название> [тег2|ссылка|name:название ...] (с пробелом в названии: name:iron_man или "name:iron man")',
        "search_header": '=== Результаты поиска: {tags} ===',
        "search_none": 'Ничего не найдено ни на Modrinth, ни на CurseForge. Проверьте тег: у Modrinth свои категории (technology, magic, adventure, utility, optimization и т. д.), на CurseForge названия отличаются .',
        "search_cf_skipped": 'CurseForge пропускаем: ключа нет (команда key).',
        "url_not_recognized": 'Не похоже на ссылку на категорию CurseForge/Modrinth, пропускаю: {url}',
        "no_results_yet": 'Сначала выполните search.',
        "bad_index": 'Нет такого номера.',
        "show_header": "=== {title} ===",
        "field_source": "Источник",
        "field_link": 'Ссылка',
        "field_downloads": 'Загрузок',
        "field_categories": 'Категории',
        "field_description": "Описание",
        "field_deps_none": 'Зависимостей нет.',
        "field_deps_note": 'Зависимости по последней версии, у старых могут быть другие.',
        "save_done": 'Сохранено: {path}',
        "save_error": 'Не удалось сохранить: {err}',
        "saveall_done": 'Записей сохранено: {n}',
        "bulk_usage": 'Использование: bulk <тег|ссылка|name:название> [тег|ссылка|name:название ...] (с пробелом в названии: name:iron_man или "name:iron man")',
        "bulk_header": "=== bulk: {query} ===",
        "bulk_thresholds": 'Верх категории: {pages} стр. по {size} (по скачиваниям) плюс аддоны найденных модов, до {addons} кандидатов на мод и платформу, {workers} потоков. Настройки в начале файла: TOP_PAGES, PAGE_SIZE, ADDON_SEARCH_LIMIT, HTTP_WORKERS.',
        "bulk_fetching": 'Верх категории: {source} / {tag} ...',
        "bulk_cf_category_not_found": 'Категория CurseForge «{tag}» не найдена, пропускаю.',
        "bulk_resolving": 'Ищу эти же моды на второй платформе и собираю зависимости ({n})...',
        "bulk_addons": 'Ищу аддоны (моды, которым нужны найденные), кандидатов: {n}',
        "bulk_progress": 'проверено {done}/{n}',
        "bulk_saving": 'сохраняю...',
        "bulk_addons_found": 'Найдено аддонов: {n}',
        "bulk_interrupted": 'Прервано, сохраняю то, что успело собраться.',
        "bulk_done_single": 'Готово. В списке {total} записей, новых за запуск {new} (из них аддонов {addons}). Файлы: {path} (для чтения), {ai_path} (для нейронки).',
        "origin_top": 'верх категории {src}:{tag}',
        "origin_addon": 'аддон к {name} ({dep})',
        "origin_manual": 'сохранён вручную',
        "f_desc_mr": 'Описание (Modrinth)',
        "f_desc_cf": 'Описание (CurseForge)',
        "f_found": 'Найден',
        "f_loaders": 'Версии/загрузчики',
        "file_header": 'Моды Minecraft - собрано Auto-Modpacker. Записей: {n}. Обновлено: {ts}',
        "addons_usage": 'Использование: addons <slug|modid>',
        "addons_target_not_found": 'Нет такого мода (slug/modid) ни на Modrinth, ни на CurseForge.',
        "addons_header": '=== Возможные аддоны для {name} (возможно, не все) ===',
        "addons_disclaimer": ('Modrinth/CurseForge не отдают oбратные зависимости, только собственные зависимости мода, поэтому спросить у них, кто зависит от мода, нельзя. Кандидатов беру текстовым поиcком и у каждого проверяю, есть ли в его зависимостях нужный мод. Так находятся не все аддоны: часть в поиск просто не попадает.'),
        "addons_checking": 'Проверяю кандидатов ({n})...',
        "addons_confirmed": 'Подтверждено (зависимость на {name} указана):',
        "addons_none_confirmed": 'Ни у одного кандидата нет зависимости на {name}.',
        "help_header": "=== Команды ===",
        "help_key": 'Сохраняет ключ CurseForge рядом со скриптом. Без ключa CurseForge в поиcке не участвует.',
        "help_search": 'Ищет моды на Modrinth и CurseForge. Аргумент: теги (через И) или ссылка на список категории. Выводит нумерованный список с полным описанием. Поиск по названию: name:hulk (с пробелом: name:iron_man или в кавычках), ищет моды, у кoторых эти слова есть в названии или slug, на oбеих площадках.',
        "help_show": 'Полная карточка результата N из последнегo search: описание, ссылка, зависимости и нeсовместимости (по последней версии).',
        "help_save": 'Добавляет рeзультат N в oбщий список (found_mods/mods.txt + mods_ai.txt).',
        "help_saveall": 'Добавляет в общий список все рeзультаты пoследнего search.',
        "help_bulk": ('Берёт ВЕРХ категории (тег или ссылка вида modrinth.com/discover/mods?f=categories:optimization&e=client&s=downloads или curseforge.com/minecraft/search?...&categories=performance), потом для каждого мода ищет аддоны на oбеих площадках. Запросы идут параллельно, прогресс сохраняется по ходу. Один и тот же мод с Modrinth и CurseForge собирается в одну запись. Пишет found_mods/mods.txt и found_mods/mods_ai.txt (сжатый, для нейронки). Список копится между запусками: чтобы начать с нуля, удалите папку found_mods. Вместо категории можно указать название: name:hulk, тогда берутся моды с таким словом в названии или slug (NAME_PAGES страниц на платфoрму), дальше аддоны как обычно.'),
        "help_addons": 'Ищет возможные аддоны для мода (slug на Modrinth или modId/slug на CurseForge), кандидатов прoверяет по зависимостям. Список неполный, подробноcти в самой команде.',
        "name_empty": 'После name: пусто, пропускаю.',
        "bulk_fetching_name": 'Ищу по названию: {source} / «{q}» ...',
        "origin_name": 'поиск по названию {src}:{q}',
        "bulk_collect": 'Собираю кандидатов в аддоны по названиям модов ({n})...',
        "help_build": ("Автосборка модпака: build <ссылка|slug> [forge|neoforge|fabric|quilt] [версия ...] [client|server] [mr=N] [cf=N]. Ищет аддоны главного мода на Modrinth и CurseForge по зависимостям (и аддоны аддонов), делит на блоки по загрузчику и версии Minecraft, помечает exclusive (мод только на одной версии) и 'нет на', необязательные отдельно. mr=N / cf=N не берёт моды, у которых на своeй платформе скачиваний меньше N (можно 5k, 1m). Моды с похожим назвaнием, но без зависимости, спрашивает вручную. Потом можно сделать модпак: found_mods/modpacks/<мод>_<загрузчик>_<версия>/mods с готовыми .jar. Отчёты: found_mods/build_<мод>.txt и build_<мод>_ai.txt. Также пакует в .mrpack, один и тот же мод на Modrinth и CurseForge ищет по хешу файла."),
        "help_importlink": ('Импорт по ссылкам: importlink [prefer CF|M|auto] [min mr=N cf=N] [версия] [загрузчик]. Спрашивает версию Minecraft и загрузчик, потом принимает ссылки Modrinth/CurseForge, по одной или спиcком (ссылки можно вставить и прямо в скрипт без команды). Для каждогo мода смотрит обе площадки и берёт самый новый файл под версию и загрузчик (1.2 новее 1.1.9, 1.2.2 новее 1.2, 2 новее 1.2), при равных версиях решает prefer (CF!/M! значит всегда эта площадка). min mr=N cf=N пропускает площадку, где у мода меньше N скачиваний (min off сбрасывает). Обязательные зависимости скачиваются автоматически (deps off выключает). Перед скачиванием спрашивает y/n и папку: новая, готовая или папка скрипта. Внутри режима есть команды prefer, min, version, loader, deps, folder, settings, exit. Самый новый файл выбирается по номеру версии (беты и альфы тоже), only releases берёт только релизы, only off возвращает выбор по номеру.'),
        "help_update": 'Обновление модов в папке: update [версия] [загрузчик] [prefer ...] [min ...]. Спрашивает папку, версию Minecraft и загрузчик сборки, определяет моды (по списку importlink, SHA1 на Modrinth, отпечатку CurseForge), ищет файлы новее на обеих площадках и спрaшивает, что делать: поставить все cразу, по одному или отменить. Старые файлы перемещаются в _old. only releases обновляет только до релизов.',
        "help_newaddons": ("Новые аддоны к моду за период: newaddons <ссылка|slug> [период] [загрузчик] [версия]. Период: 7d, 2w, 3m, 1y или словами (неделя, 2 недели, месяц, 3 мес, 10 дней), без периода берётся неделя. Смотрит самые свежие проекты на Modrinth и CurseForge, оставляет те, что появились за период и нуждаются в этом моде (напрямую или через другой аддон), показывает дату, плoщадки, загрузчики с версиями и ссылки. Отдельно идут 'возможные': название похoже, а зависимость не указана. Загрузчик и версия сужают список."),
        "help_slug": ('Slug — это окончание ссылки на мод. Например, для ссылки https://modrinth.com/mod/sodium slug будет sodium, для ссылки https://modrinth.com/mod/ferrite-core slug будет ferrite-core. На CurseForge slug тоже бeрётся из концa ссылки.'),
        "cancelled": "Отменено.",
        "interrupted": 'Прервано.',
        "mod_not_found": 'Мод не найден (нужна ссылка на мод Modrinth/CurseForge или его slug).',
    },
    "en": {
        "lang_prompt": "Выберите язык / Choose language [ru/en]: ",
        "banner_title": "  Auto-Modpacker by A Simple Block",
        "banner_note": 'Searches for mods on Modrinth and CurseForge. The bulk command takes the top results from a category and addons for the found mods. Everything is written to found_mods/mods.txt (readable) and found_mods/mods_ai.txt (a compact version for an AI assistant, with fewer tokens).',
        "commands": ("Commands: key <key> | search <tag|name:title|url ...> | show <N> | save <N> | saveall | "
                     "bulk <tag|name:title|url ...> | addons <slug|modid> | build <link|slug ...> | importlink | "
                     "update | newaddons | help | exit"),
        "key_set": 'The CurseForge API key has been saved next to the script.',
        "key_usage": "Usage: key <key>",
        "no_internet": "No internet, nothing to search with.",
        "net_cf_down": "CurseForge is not answering, using Modrinth only.",
        "net_mr_down": "Modrinth is not answering, using CurseForge only.",
        "auth_error": "API complains about auth (401/403), looks like the CurseForge key was not accepted.",
        "search_usage": "Usage: search <tag1|url|name:title> [tag2|url|name:title ...] (space in a title: name:iron_man or \"name:iron man\")",
        "search_header": "=== Search results: {tags} ===",
        "show_hint": "(show N for the full card)",
        "search_none": "Nothing found on Modrinth or CurseForge. Check the tag, Modrinth has its own categories (technology, magic, adventure, utility, optimization etc), names on CurseForge can be different.",
        "search_cf_skipped": "Skipping CurseForge, no key (key command).",
        "url_not_recognized": "Doesn't look like a CurseForge/Modrinth category link, skipping: {url}",
        "no_results_yet": "Do a search first.",
        "cancelled": "Cancelled.",
        "bad_index": "No result with this number.",
        "show_header": "=== {title} ===",
        "field_link": "Link",
        "field_source": "Source",
        "field_downloads": "Downloads",
        "field_categories": "Categories",
        "field_description": "Description",
        "field_deps_none": "No dependencies.",
        "field_deps_note": "Deps are from the latest version, older ones can have other deps.",
        "save_done": "Saved: {path}",
        "save_error": "Couldn't save: {err}",
        "saveall_done": "Saved entries: {n}",
        "bulk_usage": "Usage: bulk <tag|url|name:title> [tag|url|name:title ...] (space in a title: name:iron_man or \"name:iron man\")",
        "bulk_header": "=== bulk: {query} ===",
        "bulk_thresholds": "Top of category: {pages} page(s) x {size} (by downloads) plus addons of the found mods, up to {addons} candidates per mod and platform, {workers} threads. Settings are at the top of the file: TOP_PAGES, PAGE_SIZE, ADDON_SEARCH_LIMIT, HTTP_WORKERS",
        "bulk_fetching": "Top of category: {source} / {tag} ...",
        "bulk_cf_category_not_found": "No such category on CurseForge: '{tag}', skipping.",
        "bulk_resolving": "Looking for the same mods on the other platform and collecting deps ({n})...",
        "bulk_addons": "Looking for addons (mods that need the found ones), candidates: {n}",
        "bulk_progress": 'checked {done}/{n}',
        "bulk_addons_found": "Addons found: {n}",
        "bulk_interrupted": "Interrupted, saving what got collected.",
        "bulk_done_single": "Done. {total} entries in the list, {new} new this run ({addons} of them addons). Files: {path} (readable), {ai_path} (for LLM).",
        "origin_top": "top of category {src}:{tag}",
        "origin_addon": "addon of {name} ({dep})",
        "origin_manual": "saved manually",
        "file_header": "Minecraft mods - collected by Auto-Modpacker. Entries: {n}. Updated: {ts}",
        "f_desc_mr": "Description (Modrinth)",
        "f_desc_cf": "Description (CurseForge)",
        "f_found": "Found via",
        "f_loaders": "Loaders/versions",
        "addons_usage": "Usage: addons <slug|modid>",
        "addons_target_not_found": "No mod with this slug/modid on Modrinth or CurseForge.",
        "addons_header": "=== Possible addons for {name} (may be not all) ===",
        "addons_disclaimer": ("Modrinth and CurseForge provide a mod's own dependencies, but not a list of reverse dependencies. That means they cannot directly tell us which projects depend on a given mod. Candidates are found through text search, then each candidate is checked to see whether its dependency list includes the target mod. This method will not find every addon because some projects do not appear in search results."),
        "addons_checking": "Checking candidates ({n})...",
        "addons_confirmed": "Confirmed (lists {name} as a dependency):",
        "addons_none_confirmed": "None of the candidates depends on {name}.",
        "help_header": "=== Commands ===",
        "help_key": 'Saves the CurseForge API key next to the script. Without a key, CurseForge is not used for search.',
        "help_search": "Searches Modrinth and CurseForge, argumеnt is tags (AND) or a category listing link. Prints a numbered list with full descriptions. By title: name:hulk (with a space use name:iron_man or quotes), finds mods that have thеse words in title or slug, on both platforms.",
        "help_show": "Full card of result N from the last search: description, link, dependencies and incоmpatibilities (latest version).",
        "help_save": "Adds result N to the сommon list (found_mods/mods.txt + mods_ai.txt).",
        "help_saveall": "Adds all results of the last search to the cоmmon list.",
        "help_addons": "Looks for possible addons of a mod (Modrinth slug or CurseForge modId/slug), candidates are checked by dependencies. List is not completе, see the note in the cоmmand itself.",
        "help_bulk": ("Takes the TOP of a category (tag or a link like modrinth.com/discover/mods?f=categories:optimization&e=client&s=downloads "
                      "or curseforge.com/minecraft/search?...&categories=performance), then lоoks for addons of every mod on both "
                      "platforms. Requests run in parallel, progress is saved as it goes. Same mod from Modrinth and CurseForge bеcomes one "
                      "entry. Writes found_mods/mods.txt and found_mods/mods_ai.txt (compact, for an LLM). The list grows between runs, "
                      "delete found_mods to start from zero. Instead of a category you can give a title: name:hulk, then it takes mods with "
                      "that word in title/slug (NAME_PAGES pages per platform), addons after that as usual."),
        "bulk_fetching_name": "Searching by title: {source} / '{q}' ...",
        "origin_name": "title search {src}:{q}",
        "bulk_collect": "Collecting addon candidates by mod names ({n})...",
        "name_empty": "Nothing after name:, skipping.",
        "help_build": ("Modpack builder: build <link|slug> [forge|neoforge|fabric|quilt] [version ...] [client|server] [mr=N] [cf=N]. Finds addons of the main "
                       "mod on Modrinth and CurseForge by dependencies (and addons of addons), cuts them into loader + Minecraft version "
                       "blocks, mаrks exclusive (mod only on one version) and 'missing on', optional ones go separately. mr=N / cf=N skips "
                       "mods that have fewer than N downloads on their platform (5k, 1m work). Mods with a similar name but no dependency "
                       "are asked manually. Then you can make a modpack: found_mods/modpacks/<mod>_<loader>_<version>/mods with ready .jar "
                       "files. Reports are found_mods/build_<mod>.txt and build_<mod>_ai.txt. Also packs .mrpack, the same mod on Modrinth "
                       "and CurseForge is matсhed by file hash."),
        "help_importlink": ("Import by links: importlink [prefer CF|M|auto] [min mr=N cf=N] [version] [loader]. Asks Minecraft version and loader, "
                            "then takes Modrinth/CurseForge links, one by one or a list (you can also just drop links into the script without "
                            "the command). For every mod it looks at both platforms and takes the newest file for the version and loader (1.2 "
                            "is newer than 1.1.9, 1.2.2 than 1.2, 2 than 1.2), with equal versions prefer decides (CF!/M! means always this "
                            "platform). min mr=N cf=N ignоres a platform where the mod has fewer than N downloads (min off resets). Required "
                            "dependencies are downloaded too (deps off turns it off). Before downloading it asks y/n and the folder: new, "
                            "existing or the script folder. Commands insidе the mode: prefer, min, version, loader, deps, folder, settings, "
                            "exit. Newest file is picked by version number (betas and alphas too), only releases takes releases only, "
                            "only off goes back to by number."),
        "help_update": "Update mods in a folder: update [version] [loader] [prefer ...] [min ...]. Asks the folder, Minecraft version and loader of the build, identifies mods (importlink list, SHA1 on Modrinth, CurseForge fingerprint), lоoks for nеwer files on both platforms and asks what to do: install all at once, one by one, or cancel. Old files go to _old. only releases updates to releases only.",
        "help_newaddons": ("New addons of a mod for a period: newaddons <link|slug> [period] [loader] [version]. Period is 7d, 2w, 3m, 1y or "
                           "words (week, 2 weeks, month, 3 months, 10 days), no period means a week. Looks at the newest projects on Modrinth "
                           "and CurseForge, keeps the ones created in that period that need this mod (directly or through another addon), "
                           "shows date, plаtforms, loaders with versions and links. 'Possible' ones go sеparately, that is similar name but "
                           "no dependency declared. Loader and version narrow the list."),
        "help_slug": ("Slug is the end of a mod's link. For еxample, for the link https://modrinth.com/mod/sodium the "
                      "slug is sоdium, for the link https://modrinth.com/mod/ferrite-core the slug is ferrite-core. On "
                      "CurseForge the slug is also taken from the end of the link."),
        "interrupted": "Interrupted.",
        "mod_not_found": "Mod not found (give a Modrinth/CurseForge mod link or its slug).",
    },
}
assert {"ru", "en"} <= set(T), "locale table missing (E3176)"


LANG = "ru"

def _t(ru, en):
    return ru if LANG == "ru" else en

# кэш общий с основной частью скрипта: единый CACHE_PATH,
# слияние старого кэша происходит после _init_auto_finder()

#F68

def dump_json(obj, name="dump.json"):
    with open(os.path.join(SCRIPT_DIR, name), "w", encoding="utf-8") as f:
        json.dump(obj, f, ensure_ascii=False, indent=1)

def say(line=""):
    print(line)

#F12
_LAST_REQ = {}
_HTTP_LOCK = threading.Lock()
_AUTH_WARNED = set()


def _note_auth_error(host):
    if host in _AUTH_WARNED:
        return
    _AUTH_WARNED.add(host)
    say(f"{YELLOW}[{host}] {T[LANG]['auth_error']}{RESET}")

def http_get_json(url, headers=None):
    host = urllib.parse.urlparse(url).netloc
    gap = 0.22 if "modrinth" in host else 0.08  #F13
    for attempt in range(5):
        if _CANCEL.is_set():
            return None
        with _HTTP_LOCK:
            wait = gap - (time.time() - _LAST_REQ.get(host, 0))
            if wait > 0:
                time.sleep(wait)
            _LAST_REQ[host] = time.time()
        try:
            req = urllib.request.Request(url, headers=headers or {'User-Agent': "auto-modpacker"})
            with urllib.request.urlopen(req, timeout=15) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            if e.code in (401, 403):
                _note_auth_error(host)
                return None
            if e.code in (429, 500, 502, 503, 504) and attempt < 4:
                try:
                    delay = float(e.headers.get('Retry-After') or e.headers.get('X-Ratelimit-Reset') or 0)
                except (TypeError, ValueError, AttributeError):
                    delay = 0
                _CANCEL.wait(min(max(delay, 2 ** attempt), 65))
                continue
            return None
        except (urllib.error.URLError, TimeoutError, ValueError, OSError):
            if attempt < 2:
                time.sleep(1 + attempt)
                continue
            return None
    return None

def _ping(url):
    try:
        urllib.request.urlopen(url, timeout=5)
        return True
    except urllib.error.HTTPError:
        return True
    except Exception:
        return False

def check_internet():
    ok_mr = _ping("https://api.modrinth.com/v2")
    ok_cf = _ping("https://api.curseforge.com/v1")
    if not ok_mr and not ok_cf:
        return False
    if ok_mr and not ok_cf:
        say(YELLOW + T[LANG]['net_cf_down'] + RESET)
    if ok_cf and not ok_mr:
        say(f"{YELLOW}{T[LANG]['net_mr_down']}{RESET}")
    return True

_CANCEL = threading.Event()  #F3

def _parallel_map(fn, items, workers=HTTP_WORKERS):  #F70
    items = list(items)
    if not items:
        return

    def _run(it):
        if _CANCEL.is_set():
            return None
        return fn(it)

    pool = concurrent.futures.ThreadPoolExecutor(max_workers=min(workers, len(items)))
    try:
        futs = [pool.submit(_run, it) for it in items]
        for fut in concurrent.futures.as_completed(futs):
            try:
                fut.result()
            except Exception:
                pass
    except BaseException:
        _CANCEL.set()
        pool.shutdown(wait=False, cancel_futures=True)
        raise
    pool.shutdown(wait=True)

#F14

CF_SORT_FIELD = {"featured": 1, "relevancy": 1, "relevance": 1, "popularity": 2, "last updated": 3,
                 "lastupdated": 3, "latest update": 3, "updated": 3, "name": 4, "a-z": 4, "author": 5,
                 "total downloads": 6, "totaldownloads": 6, "downloads": 6, "category": 7, "game version": 8,
                 "gameversion": 8, "creation date": 11, "created": 11, "released date": 11, "releaseddate": 11,
                 "rating": 12}
assert CF_SORT_FIELD["downloads"] == 6, "sort field map changed (E6323)"

def cf_sort_from_url(raw):
    key = re.sub(r"[\s_+]+", " ", (raw or "").strip().lower())
    return CF_SORT_FIELD.get(key, 6)

def parse_listing_url(url):
    try:
        parsed = urllib.parse.urlparse(url)
    except ValueError:
        return None
    host = parsed.netloc.lower()
    qs = urllib.parse.parse_qs(parsed.query)
    if "curseforge.com" in host:
        tags = []
        for val in (qs.get('categories') or qs.get('category') or []):
            tags.extend(p.strip() for p in val.split(",") if p.strip())
        if not tags:
            return None
        return {'source': "curseforge", 'tags': tags, 'loaders': [], 'versions': [], 'env': "", 'sort': "downloads",
                'cf_sort': cf_sort_from_url((qs.get('sortBy') or qs.get('sort') or [""])[0])}
    if "modrinth.com" in host:
        def cats(key):
            out = []
            for val in qs.get(key, []):
                for part in val.split(","):
                    part = part.strip()
                    if part.lower().startswith("categories:"):
                        out.append(part.split(":", 1)[1].strip().lower())
            return out
        tags, loaders = cats("f"), cats("g")
        versions = [v.strip() for val in qs.get('v', []) for v in val.split(",") if v.strip()]
        if not tags and not loaders:
            return None
        return {'source': "modrinth", 'tags': tags, 'loaders': loaders, 'versions': versions,
                'env': (qs.get('e') or [""])[0].lower(), 'sort': (qs.get('s') or ["downloads"])[0].lower()}
    return None


def is_url(text):
    return text.startswith("http://") or text.startswith("https://")

NAME_PREFIXES = ("name:", "n:", "название:") #Ftemp1


def parse_name_arg(a):
    low = a.lower()
    for pre in NAME_PREFIXES:
        if low.startswith(pre):
            return _ws(re.sub(r"[_+]+", " ", a[len(pre):]))
    return None

def _name_match(query, *parts):
    words = [w for w in (_blob(x) for x in re.split(r"[\W_]+", query or "")) if w]
    if not words:
        return False
    blob = _blob(*parts)
    return all(w in blob for w in words)

def mr_name_ok(query, h):
    return _name_match(query, h.get("title"), h.get("slug"), h.get("description") if NAME_MATCH_DESC else "")

def cf_name_ok(query, h):
    return _name_match(query, h.get("name"), h.get("slug"), h.get("summary") if NAME_MATCH_DESC else "")

#F15

def cf_only_mods(items):
    out = []
    for h in items or []:
        cid = h.get("classId")
        if cid is None or cid == CF_CLASS_ID_MODS:
            out.append(h)
    return out

def mr_only_mods(hits):
    out = []
    for h in hits or []:
        pt = h.get("project_type")
        if pt == None or pt == MR_PROJECT_TYPE_MOD:
            out.append(h)
    return out

#F16

def modrinth_search(tags, limit=10):
    cache_key = "mr_search_v3f:{}".format(','.join(sorted(t.lower() for t in tags)))
    cached = cache_get(cache_key)
    if cached != "MISS":
        return mr_only_mods(cached)
    facets = [["project_type:mod"]] + [[f"categories:{t.lower()}"] for t in tags]
    url = f"https://api.modrinth.com/v2/search?query=&facets={urllib.parse.quote(json.dumps(facets))}&limit={limit}"
    data = http_get_json(url)
    hits = data.get("hits", []) if data else []
    if data is not None:
        cache_set(cache_key, hits)
    return mr_only_mods(hits)


def modrinth_search_text(query, limit=10):
    cache_key = "mr_text_v3s:{}:{}".format(limit, query.lower())
    cached = cache_get(cache_key)
    if cached != "MISS":
        return mr_only_mods(cached)
    url = (f"https://api.modrinth.com/v2/search?query={urllib.parse.quote(query)}"
           f"&facets={urllib.parse.quote(json.dumps([['project_type:mod']]))}&limit={limit}")
    data = http_get_json(url)
    hits = data.get("hits", []) if data else []
    if data is not None:
        cache_set(cache_key, hits)
    return mr_only_mods(hits)


def modrinth_project(project_id_or_slug):
    cache_key = f"mr_proj_v1n:{project_id_or_slug}"
    cached = cache_get(cache_key)
    if cached != "MISS":
        return cached
    data = http_get_json("https://api.modrinth.com/v2/project/{}".format(project_id_or_slug))
    if data is not None:
        cache_set(cache_key, data)
    return data

def _mr_fetch_version_data(project_id_or_slug):
    data = http_get_json(f"https://api.modrinth.com/v2/project/{project_id_or_slug}/version")
    if not isinstance(data, list):
        return None
    ordered = sorted((v for v in data if isinstance(v, dict)),
                     key=lambda v: v.get("date_published") or "", reverse=True)
    deps = []
    if ordered:
        for dep in ordered[0].get("dependencies", []) or []:
            deps.append([dep.get("dependency_type"), dep.get("project_id"), dep.get("file_name")])
    loaders = {}
    for v in ordered:
        gvs = v.get("game_versions") or []
        for raw in v.get("loaders") or []:
            loaders.setdefault(_loader_label(raw), set()).update(gvs)
    loaders = {k: sorted(s, key=_ver_key) for k, s in loaders.items()}
    cache_set("mr_deps_v1v:{}".format(project_id_or_slug), deps)
    cache_set("mr_loadver_v1t:{}".format(project_id_or_slug), loaders)
    return deps, loaders

def modrinth_latest_version_deps(project_id_or_slug):
    cache_key = f"mr_deps_v1v:{project_id_or_slug}"
    cached = cache_get(cache_key)
    if cached != "MISS":
        return cached
    res = _mr_fetch_version_data(project_id_or_slug)
    return res[0] if res else []



def modrinth_loader_versions(project_id_or_slug):
    if not project_id_or_slug:
        return {}
    cache_key = f"mr_loadver_v1t:{project_id_or_slug}"
    cached = cache_get(cache_key)
    if cached != "MISS":
        return cached
    res = _mr_fetch_version_data(project_id_or_slug)
    return res[1] if res else {}


def modrinth_name_for(project_id):
    if not project_id:
        return project_id
    p = modrinth_project(project_id)
    if p:
        return p.get('title', project_id)
    return project_id

def card_from_mr_project(p):
    slug = p.get("slug")
    return {"source": "Modrinth", "id": p.get("id"), "slug": slug, "title": p.get("title", "?"),
            "description": p.get("description", ""), "downloads": p.get("downloads", 0),
            "categories": p.get("categories", []) or [],
            "client_side": p.get("client_side"), "server_side": p.get("server_side"),
            "link": "https://modrinth.com/mod/{}".format(slug or p.get('id'))}



def _mr_pages(facets, index, query="", pages=None):
    hits = []
    for p in range(pages or TOP_PAGES):
        url = (f"https://api.modrinth.com/v2/search?query={urllib.parse.quote(query)}&index={index}"
               f"&facets={urllib.parse.quote(json.dumps(facets))}&limit={PAGE_SIZE}&offset={p * PAGE_SIZE}")
        data = http_get_json(url)
        if data is None:
            return hits, ("fail_first" if p == 0 else "fail_later")
        page = data.get("hits", [])
        hits.extend(page)
        if len(page) < PAGE_SIZE:
            break
    return hits, "ok"

def modrinth_top(task):
    index = task.get("sort") if task.get("sort") in ("relevance", "downloads", "follows", "newest", "updated") else "downloads"
    query = (task.get("query") or "").strip()   #F17
    pages = NAME_PAGES if query else TOP_PAGES
    base = [["project_type:mod"]] + [[f"categories:{t.lower()}"] for t in task["tags"]]
    if task.get("loaders"):
        base.append([f"categories:{x.lower()}" for x in task["loaders"]])
    if task.get("versions"):
        base.append([f"versions:{v}" for v in task["versions"]])
    env_vals = MR_ENV_CLIENT if task.get("env") == "client" else MR_ENV_SERVER if task.get("env") == "server" else None
    facets = base + ([[f"environment:{v}" for v in env_vals]] if env_vals else [])
    if query:
        cache_key = f"mr_topq_v1r:{query.lower()}:{json.dumps(facets)}:{index}:{pages}:{PAGE_SIZE}"
    else:
        cache_key = f"mr_top_v2p:{json.dumps(facets)}:{index}:{TOP_PAGES}:{PAGE_SIZE}"

    def _done(hits):
        hits = mr_only_mods(hits)
        return [h for h in hits if mr_name_ok(query, h)] if query else hits

    cached = cache_get(cache_key)


    if cached != "MISS":
        return _done(cached)
    hits, status = _mr_pages(facets, index, query, pages)
    if status == "fail_first" and env_vals:
        hits, status = _mr_pages(base, index, query, pages)
        hits = [h for h in hits if not h.get("environment") or set(env_vals) & set(h["environment"])]
    if status == "ok":
        cache_set(cache_key, hits)
    return _done(hits)

#F18

def cf_headers(api_key):
    return {"x-api-key": api_key, "Accept": "application/json"}


def cf_search(query, api_key, category_id=None, limit=10):
    cache_key = f"cf_search_v4w:{limit}:{query.lower()}:{category_id}"
    cached = cache_get(cache_key)
    if cached != "MISS":
        return cf_only_mods(cached)
    url = (f"https://api.curseforge.com/v1/mods/search?gameId=432&classId={CF_CLASS_ID_MODS}"
           f"&searchFilter={urllib.parse.quote(query)}&pageSize={limit}")
    if category_id:
        url += "&categoryId={}".format(category_id)
    data = http_get_json(url, headers=cf_headers(api_key))
    items = data.get("data", []) if data else []
    if data is not None:
        cache_set(cache_key, items)
    return cf_only_mods(items)

#F3_2

def cf_top(category_id, api_key, sort_field=6):
    cache_key = f"cf_top_v3j:{category_id}:{sort_field}:{TOP_PAGES}:{PAGE_SIZE}"
    cached = cache_get(cache_key)
    if cached != "MISS":
        return cf_only_mods(cached)
    order = "asc" if sort_field in (4, 5) else "desc"
    items, ok = [], True
    for p in range(TOP_PAGES):
        url = (f"https://api.curseforge.com/v1/mods/search?gameId=432&classId={CF_CLASS_ID_MODS}"
               f"&categoryId={category_id}&pageSize={PAGE_SIZE}&index={p * PAGE_SIZE}"
               f"&sortField={sort_field}&sortOrder={order}")
        data = http_get_json(url, headers=cf_headers(api_key))
        if data is None:
            ok = False
            break
        page = data.get('data', [])
        items.extend(page)
        if len(page) < PAGE_SIZE:
            break
    if ok:
        cache_set(cache_key, items)
    return cf_only_mods(items)

def cf_name_top(query, api_key, pages=None):
    t0 = time.time()
    pages = pages or NAME_PAGES
    cache_key = f"cf_nametop_v1a:{query.lower()}:{pages}:{PAGE_SIZE}"
    cached = cache_get(cache_key)
    if cached != "MISS":
        return [h for h in cf_only_mods(cached) if cf_name_ok(query, h)]
    items, ok = [], True
    for p in range(pages):
        url = (f"https://api.curseforge.com/v1/mods/search?gameId=432&classId={CF_CLASS_ID_MODS}"
               f"&searchFilter={urllib.parse.quote(query)}&pageSize={PAGE_SIZE}&index={p * PAGE_SIZE}"
               f"&sortField=2&sortOrder=desc")
        data = http_get_json(url, headers=cf_headers(api_key))
        if data is None:
            ok = False
            break
        page = data.get("data", [])
        items.extend(page)
        if len(page) < PAGE_SIZE:
            break
    if ok:
        cache_set(cache_key, items)
    return [h for h in cf_only_mods(items) if cf_name_ok(query, h)]


def cf_categories(api_key):
    cache_key = f"cf_categories_v2a:{CF_CLASS_ID_MODS}"
    cached = cache_get(cache_key, ttl=CATEGORY_TTL_SECONDS)
    if cached != "MISS":
        return cached
    data = http_get_json(
        "https://api.curseforge.com/v1/categories?gameId=432&classId={}".format(CF_CLASS_ID_MODS),
        headers=cf_headers(api_key),
    )
    items = data.get("data", []) if data else []
    if data is not None:
        cache_set(cache_key, items)
    return items

def cf_category_id_for_tag(tag, api_key):
    #F19
    want = re.sub(r"[\W_]+", "", (tag or "").casefold())
    for c in cf_categories(api_key):
        for field in ("slug", "name"):
            if want and re.sub(r"[\W_]+", "", (c.get(field) or "").casefold()) == want:
                return c.get('id')
    return None


def cf_mod_by_slug(slug, api_key):
    cache_key = f"cf_slug_v3b:{slug.lower()}"
    cached = cache_get(cache_key)
    if cached != "MISS":
        return cached
    url = (f"https://api.curseforge.com/v1/mods/search?gameId=432&classId={CF_CLASS_ID_MODS}"
           f"&slug={urllib.parse.quote(slug)}")
    data = http_get_json(url, headers=cf_headers(api_key))
    items = cf_only_mods(data.get("data", []) if data else [])
    result = items[0] if items else None
    if data is not None:
        cache_set(cache_key, result)
    return result


def cf_mod_by_id(mod_id, api_key):
    cache_key = f"cf_mod_v1z:{mod_id}"
    cached = cache_get(cache_key)
    if cached != "MISS":
        return cached
    data = http_get_json(f"https://api.curseforge.com/v1/mods/{mod_id}", headers=cf_headers(api_key))
    result = data.get("data") if data else None
    if data is not None:
        cache_set(cache_key, result)
    return result


def cf_latest_file_deps(mod_id, api_key):
    cache_key = f"cf_deps_v1t:{mod_id}"
    cached = cache_get(cache_key)
    if cached != "MISS":
        return cached
    data = http_get_json(f"https://api.curseforge.com/v1/mods/{mod_id}/files?pageSize=1", headers=cf_headers(api_key))
    result = []
    files = data.get('data') if data else None
    if files:
        for dep in files[0].get('dependencies', []) or []:
            kind = CF_RELATION_TYPE.get(dep.get('relationType'), "embedded")
            result.append((kind, dep.get('modId')))
    if data is not None:
        cache_set(cache_key, result)
    return result

def cf_loader_versions(mod_id, api_key):
    skipped = 0
    if not api_key:
        return {}
    m = cf_mod_by_id(mod_id, api_key)
    if not m:
        return {}
    out = {}
    for idx in m.get("latestFilesIndexes") or []:
        loader = CF_MODLOADER_NAME.get(idx.get("modLoader"))
        gv = idx.get("gameVersion")
        if not loader or not gv:
            continue
        out.setdefault(loader, set()).add(gv)
    return {k: sorted(v, key=_ver_key) for k, v in out.items()}


def cf_name_for(mod_id, api_key):
    if not mod_id:
        return str(mod_id)
    m = cf_mod_by_id(mod_id, api_key)
    if m:
        return m.get("name", str(mod_id))
    return str(mod_id)

#F20
def normalize_modrinth_hit(hit):
    return {
        "source": "Modrinth",
        "id": hit.get("project_id") or hit.get("slug"),
        "slug": hit.get("slug"),
        "title": hit.get("title", "?"),
        "description": hit.get("description", ""),
        "downloads": hit.get("downloads", 0),
        "categories": hit.get("categories", []) or hit.get("display_categories", []) or [],
        "client_side": hit.get("client_side"), "server_side": hit.get("server_side"),
        "link": f"https://modrinth.com/mod/{hit.get('slug', hit.get('project_id'))}",
    }



def normalize_cf_hit(hit):
    links = hit.get('links') or {}
    return {
        'source': "CurseForge",
        'id': hit.get('id'),
        'slug': hit.get('slug'),
        'title': hit.get('name', "?"),
        'description': hit.get('summary', ""),
        'downloads': hit.get('downloadCount', 0),
        'categories': [c.get('name') for c in (hit.get('categories') or [])],
        'isClientOnly': hit.get('isClientOnly') if isinstance(hit.get('isClientOnly'), bool) else None,
        'isServerOnly': hit.get('isServerOnly') if isinstance(hit.get('isServerOnly'), bool) else None,
        'link': links.get('websiteUrl') or f"https://www.curseforge.com/minecraft/mc-mods/{hit.get('slug')}", #Ftemp5
    }

def fetch_deps_for(card, api_key):
    result = {"required": [], "optional": [], "incompatible": [], "embedded": []}
    if card["source"] == "Modrinth":
        for dep_type, proj_id, file_name in modrinth_latest_version_deps(card["id"]):
            if dep_type not in result:
                continue
            name = modrinth_name_for(proj_id) if proj_id else (file_name or "?")
            result[dep_type].append(name)
    else:
        if not api_key:
            return result
        for kind, dep_id in cf_latest_file_deps(card["id"], api_key):
            name = cf_name_for(dep_id, api_key)
            result[kind].append(name)
    return result

#F21

def _ws(s):
    return re.sub(r"\s+", " ", s or "").strip()

def norm_title(s):
    s = re.sub(r"[\(\[].*?[\)\]]", " ", (s or "").casefold())
    return re.sub(r"[\W_]+", "", s)


def _blob(*parts):
    return re.sub(r"[\W_]+", "", " ".join(p or "" for p in parts).casefold())

def _titles_similar(a, b):
    na, nb = norm_title(a), norm_title(b)
    if not na or not nb:
        return False
    return na == nb or difflib.SequenceMatcher(None, na, nb).ratio() >= 0.85

def edit_distance_capped(a, b, cap):
    if a == b:
        return 0
    if abs(len(a) - len(b)) >= cap:
        return cap
    if len(a) < len(b):
        a, b = b, a
    prev = [min(j, cap) for j in range(len(b) + 1)]
    for i, ca in enumerate(a, 1):
        cur = [cap] * (len(b) + 1)
        cur[0] = min(i, cap)
        for j in range(max(1, i - cap), min(len(b), i + cap) + 1):
            v = min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != b[j - 1]))
            cur[j] = v if v < cap else cap
        prev = cur
        if min(cur) >= cap:
            return cap
    return min(prev[len(b)], cap)

def descriptions_differ(a, b):
    a, b = _ws(a).casefold(), _ws(b).casefold()
    return edit_distance_capped(a, b, DESC_DIFF_MIN) >= DESC_DIFF_MIN


def _ver_key(v):
    parts = re.findall(r"\d+", v or "")
    if parts:
        return (0, tuple(int(p) for p in parts))
    return (1, v or "")

def _loader_label(raw):
    key = (raw or "").strip().lower()
    return MR_LOADER_LABEL.get(key, key.capitalize() if key else "?")

#F22

_STORE = None
_REDIRECT = {}  #F6
_DEP_KINDS = ("required", "optional", "incompatible", "embedded")
_STORE_LOCK = threading.RLock()


def _ent_title(e):
    return (e.get("mr") or e.get("cf") or {}).get("title", "?")


def _store_load():
    global _STORE
    if _STORE is not None:
        return _STORE
    _STORE = []
    try:
        with open(STORE_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, list):
            _STORE = [e for e in data if isinstance(e, dict) and (e.get("mr") or e.get("cf"))]
    except (OSError, ValueError):
        pass
    for e in _STORE:
        e.setdefault("deps", {})
        for k in _DEP_KINDS:
            e["deps"].setdefault(k, [])
        e.setdefault("origins", [])
        e.setdefault("deps_done", [])
        e.setdefault("loaders", {})
        e.setdefault("loaders_done", [])
        e["nt"] = norm_title(_ent_title(e))
    return _STORE

def _store_find(card):
    store = _store_load()
    side = "mr" if card["source"] == "Modrinth" else "cf"
    for e in store:
        cur = e.get(side)
        if cur and cur.get("id") == card.get("id"):
            return e
    nt = norm_title(card.get("title"))
    slug = (card.get("slug") or "").lower()
    for e in store:
        if e.get(side):
            continue
        base = e.get("mr") or e.get("cf")
        same_slug = bool(slug) and slug == (base.get("slug") or "").lower()
        if (same_slug or (nt and nt == e.get("nt"))) and _titles_similar(base.get("title"), card.get("title")):
            return e
    return None

def _merge_deps(ent, deps):
    for k in _DEP_KINDS:
        for name in (deps or {}).get(k, []) or []:
            if name and name not in ent['deps'][k]:
                ent['deps'][k].append(name)


def _merge_loaders(ent, loaders):
    bucket = ent.setdefault("loaders", {})
    for name, vers in (loaders or {}).items():
        cur = set(bucket.get(name, []))
        cur.update(vers)
        bucket[name] = sorted(cur, key=_ver_key)

def store_add(card, deps=None, origin=None):
    with _STORE_LOCK:
        store = _store_load()
        ent = _store_find(card)
        side = "mr" if card['source'] == "Modrinth" else "cf"
        if ent is None:
            ent = {'mr': None, 'cf': None, 'deps': {k: [] for k in _DEP_KINDS}, 'origins': [],
                   'deps_done': [], 'loaders': {}, 'loaders_done': [], 'nt': norm_title(card.get('title'))}
            store.append(ent)
        if not ent.get(side):
            ent[side] = card
        _merge_deps(ent, deps)
        if origin and origin not in ent['origins']:
            ent['origins'].append(origin)
        return ent

def _store_merge(keep, drop):
    for side in ("mr", "cf"):
        if not keep.get(side) and drop.get(side):
            keep[side] = drop[side]
    _merge_deps(keep, drop.get("deps"))
    _merge_loaders(keep, drop.get("loaders"))
    for o in drop.get("origins", []):
        if o not in keep["origins"]:
            keep["origins"].append(o)
    for s in drop.get("deps_done", []):
        if s not in keep["deps_done"]:
            keep["deps_done"].append(s)
    for s in drop.get("loaders_done", []):
        if s not in keep.setdefault("loaders_done", []):
            keep["loaders_done"].append(s)
    store = _store_load()
    for i, e in enumerate(store):
        if e is drop:
            del store[i]
            break
    _REDIRECT[id(drop)] = (drop, keep)


def _canon(e):
    while id(e) in _REDIRECT:
        e = _REDIRECT[id(e)][1]
    return e

def _attach(ent, card):
    with _STORE_LOCK:
        side = "mr" if card["source"] == "Modrinth" else "cf"
        if ent.get(side):
            return
        for e in _store_load():
            if e is not ent and e.get(side) and e[side].get("id") == card.get("id"):
                _store_merge(ent, e)
                return
        ent[side] = card


def _resolve_other_side(ent, api_key):

#F23

    if ent.get("mr") and ent.get("cf"):
        return
    if ent.get("mr"):
        if not api_key:
            return
        base = ent["mr"]
        hit = cf_mod_by_slug(base["slug"], api_key) if base.get("slug") else None
        if hit and not _titles_similar(hit.get("name"), base.get("title")):
            hit = None
        if not hit:
            for h in cf_search(base.get("title") or "", api_key, limit=10):
                if _titles_similar(h.get("name"), base.get("title")):
                    hit = h
                    break
        if hit:
            _attach(ent, normalize_cf_hit(hit))
    elif ent.get("cf"):
        base = ent["cf"]
        proj = modrinth_project(base["slug"]) if base.get("slug") else None
        card = None
        if proj and proj.get("project_type", "mod") == "mod" and _titles_similar(proj.get("title"), base.get("title")):
            card = card_from_mr_project(proj)
        else:
            for h in modrinth_search_text(base.get("title") or ""):
                if _titles_similar(h.get("title"), base.get("title")):
                    card = normalize_modrinth_hit(h)
                    break
        if card:
            _attach(ent, card)

def _enrich(ent, api_key):
    with _STORE_LOCK:
        done = ent.setdefault("deps_done", [])
        ldone = ent.setdefault("loaders_done", [])
        todo = [side for side in ("mr", "cf") if ent.get(side) and not (side == "cf" and not api_key)]
    for side in todo:
        card = ent.get(side)
        if side not in done:
            deps = fetch_deps_for(card, api_key)
            with _STORE_LOCK:
                _merge_deps(ent, deps)
                done.append(side)
        if side not in ldone:
            loaders = modrinth_loader_versions(card.get("id") or card.get("slug")) if side == "mr" \
                else cf_loader_versions(card["id"], api_key)
            with _STORE_LOCK:
                _merge_loaders(ent, loaders)
                ldone.append(side)

def write_card_file(card, deps):
    try:
        store_add(card, deps, origin=T[LANG]['origin_manual'])
        return store_flush()
    except OSError as e:
        say(T[LANG]['save_error'].format(err=e))
        return None

#F24

def _render_entry(i, e, tr):
    mr, cf = e.get('mr'), e.get('cf')
    lines = ["[{}] {}".format(i, _ent_title(e))]
    if mr:
        lines.append("    Modrinth: {}  ({}: {})".format(mr.get('link'), tr['field_downloads'], mr.get('downloads', 0)))
    if cf:
        lines.append(f"    CurseForge: {cf.get('link')}  ({tr['field_downloads']}: {cf.get('downloads', 0)})")
    cats = []
    for card in (mr, cf):
        for c in (card or {}).get('categories') or []:
            if c and c not in cats:
                cats.append(c)
    lines.append(f"    {tr['field_categories']}: {', '.join(cats) or '-'}")
    loaders = e.get('loaders') or {}
    if loaders:
        lines.append(f"    {tr['f_loaders']}:")
        known = [n for n in LOADER_ORDER if n in loaders]
        extra = sorted(n for n in loaders if n not in LOADER_ORDER)
        for name in known + extra:
            vers = loaders.get(name)
            if vers:
                lines.append(f"      {name} ({', '.join(vers)})")
    dm = _ws(mr.get('description')) if mr else ""
    dc = _ws(cf.get('description')) if cf else ""
    if dm and dc and descriptions_differ(dm, dc):
        lines.append(f"    {tr['f_desc_mr']}: {dm}")
        lines.append(f"    {tr['f_desc_cf']}: {dc}")
    else:
        lines.append(f"    {tr['field_description']}: {dm or dc or '-'}")
    for kind in _DEP_KINDS:
        names = (e.get('deps') or {}).get(kind) or []
        if names:
            lines.append(f"    {DEP_TYPE_LABEL[kind][LANG]}: {', '.join(names)}")
    if e.get('origins'):
        lines.append(f"    {tr['f_found']}: {'; '.join(e['origins'])}")
    return lines

_DEP_TAG = {"required": "req", "optional": "opt", "incompatible": "inc", "embedded": "emb"}

def _render_entry_compact(e):
    mr, cf = e.get('mr'), e.get('cf')
    parts = [_ent_title(e)]

    dl = []
    if mr:
        dl.append(f"M{mr.get('downloads', 0)}")
    if cf:
        dl.append(f"C{cf.get('downloads', 0)}")
    if dl:
        parts.append("dl:" + ",".join(dl))

    cats = []
    for card in (mr, cf):
        for c in (card or {}).get('categories') or []:
            if c and c not in cats:
                cats.append(c)
    if cats:
        parts.append("cat:" + ",".join(cats))

    dm = _ws(mr.get('description')) if mr else ""
    dc = _ws(cf.get('description')) if cf else ""
    d = dm or dc
    if d:
        parts.append("desc:" + d)

    for kind in _DEP_KINDS:
        names = (e.get('deps') or {}).get(kind) or []
        if names:
            parts.append(f"{_DEP_TAG[kind]}:" + ",".join(names))

    loaders = e.get('loaders') or {}
    if loaders:
        known = [n for n in LOADER_ORDER if n in loaders]
        extra = sorted(n for n in loaders if n not in LOADER_ORDER)
        lp = [f"{name}({','.join(loaders[name])})" for name in known + extra if loaders.get(name)]
        if lp:
            parts.append("ld:" + ";".join(lp))

    links = [c.get('link') for c in (mr, cf) if c and c.get('link')]
    if links:
        parts.append("url:" + " ".join(links))

    return " | ".join(parts)

_FLUSH_T = {"t": 0.0}


def store_flush_throttled(interval=20):
    now = time.time()
    with _STORE_LOCK:
        if now - _FLUSH_T['t'] < interval:
            return
        _FLUSH_T['t'] = now
    try:
        store_flush()
    except OSError:
        pass


def store_flush():
    with _STORE_LOCK:
        return _store_flush_locked()

def _store_flush_locked():
    store = _store_load()
    tr = T[LANG]
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    with open(STORE_PATH + ".tmp", "w", encoding="utf-8") as f:
        json.dump(store, f, ensure_ascii=False)
    os.replace(STORE_PATH + ".tmp", STORE_PATH)

    #F25
    lines = [tr["file_header"].format(n=len(store), ts=time.strftime("%Y-%m-%d %H:%M")), ""]
    lines.append(_t(f"История запусков bulk (последние {RUN_LOG_TAIL}):", f"Bulk run history (last {RUN_LOG_TAIL}):"))
    try:
        with open(RUN_LOG_PATH, "r", encoding="utf-8") as rf:
            log_lines = rf.readlines()
        for entry in log_lines[-RUN_LOG_TAIL:]:
            lines.append("  " + entry.rstrip("\n"))
    except OSError:
        lines.append(_t('(пока нет записей)', '(nothing yet)'))
    lines.append("")
    for i, e in enumerate(store, 1):
        lines.extend(_render_entry(i, e, tr))
        lines.append("")
    with open(ALL_MODS_PATH + ".tmp", "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    os.replace(ALL_MODS_PATH + ".tmp", ALL_MODS_PATH)

    #F26
    ai_lines = [f"# {len(store)} mods, updated {time.strftime('%Y-%m-%d %H:%M')}"]
    for i, e in enumerate(store, 1):
        ai_lines.append("{}. {}".format(i, _render_entry_compact(e)))
    with open(AI_MODS_PATH + ".tmp", "w", encoding="utf-8") as f:
        f.write("\n".join(ai_lines))
    os.replace(AI_MODS_PATH + ".tmp", AI_MODS_PATH)

    return ALL_MODS_PATH

def log_bulk_run(args_desc, total, new, addons):
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    line = f"{time.strftime('%Y-%m-%d %H:%M:%S')} | запрос: {args_desc} | всего: {total} | новых: {new} | аддонов: {addons}\n"
    try:
        with open(RUN_LOG_PATH, "a", encoding="utf-8") as f:
            f.write(line)
    except OSError:
        pass

#F27

LAST_RESULTS = []

def do_search(args, api_key):
    tr = T[LANG]
    if not args:
        say(tr["search_usage"])
        return
    if not check_internet():
        say(f"{RED}{tr['no_internet']}{RESET}")
        return

    global LAST_RESULTS
    LAST_RESULTS = []
    results = []
    url_tasks = []
    plain_tags = []
    name_queries = []

    for a in args:
        nq = parse_name_arg(a)
        if nq is not None:
            if nq:
                name_queries.append(nq)
            else:
                say(f"{YELLOW}{tr['name_empty']}{RESET}")
        elif is_url(a):
            parsed = parse_listing_url(a)
            if parsed:
                for t in (parsed["tags"] or [None]):
                    if t:
                        url_tasks.append((parsed["source"], t))
            else:
                say(YELLOW + tr['url_not_recognized'].format(url=a) + RESET)
        else:
            plain_tags.append(a)

    cf_warned = False

    if plain_tags:
        mr_hits = modrinth_search(plain_tags)
        results += [normalize_modrinth_hit(h) for h in mr_hits]
        if api_key:
            cat_id = cf_category_id_for_tag(plain_tags[0], api_key)
            cf_hits = cf_search(" ".join(plain_tags), api_key, category_id=cat_id)
            results += [normalize_cf_hit(h) for h in cf_hits]
        else:
            say(f"{YELLOW}{tr['search_cf_skipped']}{RESET}")
            cf_warned = True

    for q in name_queries:
        results += [normalize_modrinth_hit(h) for h in modrinth_search_text(q, NAME_SEARCH_LIMIT)
                    if mr_name_ok(q, h)]
        if api_key:
            results += [normalize_cf_hit(h) for h in cf_search(q, api_key, limit=NAME_SEARCH_LIMIT)
                        if cf_name_ok(q, h)]
        elif not cf_warned:
            say(YELLOW + tr['search_cf_skipped'] + RESET)
            cf_warned = True

    for source, tag in url_tasks:
        if source == "modrinth":
            hits = modrinth_search([tag])
            results += [normalize_modrinth_hit(h) for h in hits]
        else:
            if not api_key:
                if not cf_warned:
                    say(f"{YELLOW}{tr['search_cf_skipped']}{RESET}")
                    cf_warned = True
                continue
            cat_id = cf_category_id_for_tag(tag, api_key)
            if not cat_id:
                say(tr["bulk_cf_category_not_found"].format(tag=tag))
                continue
            hits = cf_search("", api_key, category_id=cat_id)
            results += [normalize_cf_hit(h) for h in hits]

    dedup, seen = [], set()
    for r in results:
        key = (r["source"], r["id"])
        if key in seen:
            continue
        seen.add(key)
        dedup.append(r)
    results = dedup

    say(f"{GREEN}{BOLD}{tr['search_header'].format(tags=', '.join(args))}{RESET}")
    if not results:
        say(tr["search_none"])
        say(tr["commands"])
        return

    for idx, r in enumerate(results, start=1):
        say(f"[{idx}] {BOLD}{r['title']}{RESET} ({r['source']}, {r['downloads']} ↓)")
        #F28
        if r["description"]:
            say(f"    {r['description']}")
    LAST_RESULTS = results
    say(tr["commands"])


def _get_result(idx_str):
    tr = T[LANG]
    if not LAST_RESULTS:
        say(tr["no_results_yet"])
        return None
    try:
        idx = int(idx_str)
    except ValueError:
        say(tr["bad_index"])
        return None
    if not (1 <= idx <= len(LAST_RESULTS)):
        say(tr["bad_index"])
        return None
    return LAST_RESULTS[idx - 1]

def _print_card(card, api_key):
    tr = T[LANG]
    say(f"{GREEN}{BOLD}{tr['show_header'].format(title=card['title'])}{RESET}")
    say(f"{tr['field_source']}: {card['source']}")
    say(f"{tr['field_link']}: {card['link']}")
    say(f"{tr['field_downloads']}: {card['downloads']}")
    say(f"{tr['field_categories']}: {', '.join(card['categories']) or '-'}")
    say(f"{tr['field_description']}: {card['description'] or '-'}")

    deps = fetch_deps_for(card, api_key)
    any_deps = False
    for kind in _DEP_KINDS:
        if deps[kind]:
            any_deps = True
            say(f"{DEP_TYPE_LABEL[kind][LANG]}:")
            for name in deps[kind]:
                say(f"  - {name}")
    if not any_deps:
        say(tr["field_deps_none"])
    say(tr["field_deps_note"])
    return deps

def do_show(args, api_key):
    tr = T[LANG]
    if not args:
        say(tr["bad_index"])
        return
    card = _get_result(args[0])
    if not card:
        return
    _print_card(card, api_key)
    say(tr["commands"])


def do_save(args, api_key):
    tr = T[LANG]
    if not args:
        say(tr["bad_index"])
        return
    card = _get_result(args[0])
    if not card:
        return
    deps = fetch_deps_for(card, api_key)
    path = write_card_file(card, deps)
    if path:
        say(tr["save_done"].format(path=os.path.relpath(path, SCRIPT_DIR)))
    say(tr["commands"])

def do_saveall(api_key):
    tr = T[LANG]
    if not LAST_RESULTS:
        say(tr["no_results_yet"])
        return
    n = 0
    try:
        for card in LAST_RESULTS:
            store_add(card, fetch_deps_for(card, api_key), origin=tr["origin_manual"])
            n += 1
        path = store_flush()
        say(tr["saveall_done"].format(n=n))
        say(tr["save_done"].format(path=os.path.relpath(path, SCRIPT_DIR)))
    except OSError as e:
        say(tr["save_error"].format(err=e))
    say(tr["commands"])

def find_dependents(targets, api_key, on_found=None):
    tr = T[LANG]
    mr_ids, cf_ids = {}, {}
    for e in targets:
        if e.get("mr"):
            mr_ids[e["mr"]["id"]] = e
        if e.get("cf"):
            cf_ids[e["cf"]["id"]] = e

    pool_mr, pool_cf = {}, {}
    pool_lock = threading.Lock()
    cprog = {"done": 0}
    say(tr["bulk_collect"].format(n=len(targets)))

    def _collect(e):
        title = _ent_title(e)
        nt = _blob(title)
        if not nt:
            return
        mr_new = [h for h in modrinth_search_text(title, ADDON_SEARCH_LIMIT)
                  if nt in _blob(h.get("title"), h.get("slug"), h.get("description"))]
        cf_new = []
        if api_key:
            cf_new = [h for h in cf_search(title, api_key, limit=ADDON_SEARCH_LIMIT)
                      if nt in _blob(h.get("name"), h.get("slug"), h.get("summary"))]
        with pool_lock:
            for h in mr_new:
                pid = h.get("project_id")
                if pid and pid not in mr_ids:
                    pool_mr.setdefault(pid, h)
            for h in cf_new:
                cid = h.get("id")
                if cid and cid not in cf_ids:
                    pool_cf.setdefault(cid, h)
            cprog["done"] += 1
            if cprog["done"] % 50 == 0:
                say(tr["bulk_progress"].format(done=cprog["done"], n=len(targets)))

    _parallel_map(_collect, targets)

    n = len(pool_mr) + len(pool_cf)
    say(tr["bulk_addons"].format(n=n))
    found = []
    progress = {"done": 0}
    lock = threading.Lock()

    def _bump():
        with lock:
            progress["done"] += 1
            if progress["done"] % 25 == 0:
                say(tr["bulk_progress"].format(done=progress["done"], n=n))

    def _check_mr(item):
        pid, h = item
        matches = [(mr_ids[dp], dt) for dt, dp, _fn in modrinth_latest_version_deps(pid)
                   if dp in mr_ids and dt in ("required", "optional")]
        _bump()
        if matches:
            card = normalize_modrinth_hit(h)
            found.append((card, matches))
            if on_found:
                on_found(card, matches)

    def _check_cf(item):
        cid, h = item
        matches = [(cf_ids[dp], dk) for dk, dp in cf_latest_file_deps(cid, api_key)
                   if dp in cf_ids and dk in ("required", "optional")]
        _bump()
        if matches:
            card = normalize_cf_hit(h)
            found.append((card, matches))
            if on_found:
                on_found(card, matches)

    _parallel_map(_check_mr, pool_mr.items())
    if api_key:
        _parallel_map(_check_cf, pool_cf.items())
    return found


def do_bulk(args, api_key):
    dbg = False
    tr = T[LANG]
    if not args:
        say(tr["bulk_usage"])
        return
    if not check_internet():
        say(f"{RED}{tr['no_internet']}{RESET}")
        return
    tasks = []
    for a in args:
        nq = parse_name_arg(a)
        if nq is not None:
            if not nq:
                say(f"{YELLOW}{tr['name_empty']}{RESET}")
                continue
            base = {"loaders": [], "versions": [], "env": "", "sort": "relevance", "query": nq}
            tasks.append(dict(base, source="modrinth", tags=[]))
            if api_key:
                tasks.append(dict(base, source="curseforge", tags=[]))
        elif is_url(a):
            p = parse_listing_url(a)
            if p:
                tasks.append(p)
            else:
                say(YELLOW + tr['url_not_recognized'].format(url=a) + RESET)
        else:
            base = {"loaders": [], "versions": [], "env": "", "sort": "downloads"}
            tasks.append(dict(base, source="modrinth", tags=[a]))
            if api_key:
                tasks.append(dict(base, source="curseforge", tags=[a]))
    if not tasks:
        return

    _CANCEL.clear()
    store = _store_load()
    before = len(store)
    say(f"{GREEN}{BOLD}{tr['bulk_header'].format(query=', '.join(args))}{RESET}")
    say(tr["bulk_thresholds"].format(pages=TOP_PAGES, size=PAGE_SIZE, addons=ADDON_SEARCH_LIMIT, workers=HTTP_WORKERS))
    say()

    top, addon_ents = [], []
    cf_warned = False
    try:
        for t in tasks:
            label = "+".join(t["tags"] + t.get("loaders", []))
            if t["source"] == "modrinth":
                if t.get("query"):
                    say(tr["bulk_fetching_name"].format(source="Modrinth", q=t["query"]))
                    origin = tr["origin_name"].format(src="modrinth", q=t["query"])
                else:
                    say(tr["bulk_fetching"].format(source="Modrinth", tag=label))
                    origin = tr["origin_top"].format(src="modrinth", tag=label)
                for hit in modrinth_top(t):
                    top.append(store_add(normalize_modrinth_hit(hit), None, origin))
            else:
                if not api_key:
                    if not cf_warned:
                        say(f"{YELLOW}{tr['search_cf_skipped']}{RESET}")
                        cf_warned = True
                    continue
                if t.get("query"):
                    say(tr["bulk_fetching_name"].format(source="CurseForge", q=t["query"]))
                    origin = tr["origin_name"].format(src="curseforge", q=t["query"])
                    for item in cf_name_top(t["query"], api_key):
                        top.append(store_add(normalize_cf_hit(item), None, origin))
                    continue
                for tag in t["tags"]:
                    cat_id = cf_category_id_for_tag(tag, api_key)
                    if not cat_id:
                        say(tr["bulk_cf_category_not_found"].format(tag=tag))
                        continue
                    say(tr["bulk_fetching"].format(source="CurseForge", tag=tag))
                    for item in cf_top(cat_id, api_key, t.get("cf_sort", 6)):
                        top.append(store_add(normalize_cf_hit(item), None,
                                             tr["origin_top"].format(src="curseforge", tag=tag)))
        store_flush()

        def uniq(ents):
            out, seen = [], set()
            for e in ents:
                e = _canon(e)
                if id(e) not in seen:
                    seen.add(id(e))
                    out.append(e)
            return out

        top = uniq(top)
        say(tr["bulk_resolving"].format(n=len(top)))
        _parallel_map(lambda e: _resolve_other_side(e, api_key), top)
        top = uniq(top)
        _parallel_map(lambda e: _enrich(e, api_key), top)
        store_flush()
        save_cache()

        def _on_addon_found(card, matches):
            ent = None
            for te, dk in matches:
                ent = store_add(card, None, tr["origin_addon"].format(name=_ent_title(_canon(te)), dep=dk))
            if ent is not None:
                addon_ents.append(ent)
            store_flush_throttled()

        find_dependents(top, api_key, on_found=_on_addon_found)
        addon_ents = uniq(addon_ents)
        say(tr["bulk_addons_found"].format(n=len(addon_ents)))
        _parallel_map(lambda e: _resolve_other_side(e, api_key), addon_ents)
        addon_ents = uniq(addon_ents)
        _parallel_map(lambda e: _enrich(e, api_key), addon_ents)
    except KeyboardInterrupt:
        say()
        say(f"{YELLOW}{tr['bulk_interrupted']}{RESET}")
    finally:
        try:
            path = store_flush()
        except OSError as e:
            say(tr["save_error"].format(err=e))
            path = ALL_MODS_PATH
        save_cache() #Ftemp84

    say()
    new_count = max(0, len(store) - before)
    log_bulk_run(", ".join(args), len(store), new_count, len(addon_ents))
    say(tr["bulk_done_single"].format(total=len(store), new=new_count, addons=len(addon_ents),
                                      path=os.path.relpath(path, SCRIPT_DIR),
                                      ai_path=os.path.relpath(AI_MODS_PATH, SCRIPT_DIR)))
    say(tr["commands"])

def do_addons(args, api_key):
    tr = T[LANG]
    if not args:
        say(tr['addons_usage'])
        return
    if not check_internet():
        say(f"{RED}{tr['no_internet']}{RESET}")
        return
    query = args[0]
    target = None
    mr_target = modrinth_project(query)
    if mr_target and mr_target.get('project_type', "mod") != "mod":
        mr_target = None
    if mr_target:
        target = {'id': mr_target.get('id'), 'slug': mr_target.get('slug'), 'title': mr_target.get('title', query)}
    elif api_key:
        cf_target = cf_mod_by_slug(query, api_key) or cf_mod_by_id(query, api_key)
        if cf_target and cf_target.get('classId') not in (None, CF_CLASS_ID_MODS):
            cf_target = None
        if cf_target:
            target = {'id': cf_target.get('id'), 'slug': cf_target.get('slug'), 'title': cf_target.get('name', query)}

    if not target:
        say(tr['addons_target_not_found'])
        return

    say(GREEN + BOLD + tr['addons_header'].format(name=target['title']) + RESET)
    say(tr['addons_disclaimer'])
    say()

    candidates = modrinth_search_text(target['title'])
    say(tr['addons_checking'].format(n=len(candidates)))

    confirmed = []
    for hit in candidates:
        proj_id = hit.get('project_id')
        if not proj_id or proj_id == target['id']:
            continue
        for dep_type, dep_proj_id, _fn in modrinth_latest_version_deps(proj_id):
            if dep_proj_id == target['id'] and dep_type in ("required", "optional"):
                confirmed.append((hit.get('title', proj_id), dep_type, "Modrinth"))
                break

    cf_candidates = cf_search(target['title'], api_key) if api_key else []
    if api_key:
        for hit in cf_candidates:
            cf_id = hit.get('id')
            if not cf_id or cf_id == target['id']:
                continue
            for kind, dep_id in cf_latest_file_deps(cf_id, api_key):
                if dep_id == target['id'] and kind in ("required", "optional"):
                    confirmed.append((hit.get('name', cf_id), kind, "CurseForge"))
                    break

    say()
    if confirmed:
        say(tr['addons_confirmed'].format(name=target['title']))
        for name, dep_type, source in confirmed:
            say(f"  - {BOLD}{name}{RESET} ({source}, {dep_type})")
        for name, dep_type, source in confirmed:
            pool = candidates if source == "Modrinth" else cf_candidates
            for hit in pool:
                hit_name = hit.get('title') if source == "Modrinth" else hit.get('name')
                if hit_name == name:
                    card = normalize_modrinth_hit(hit) if source == "Modrinth" else normalize_cf_hit(hit)
                    deps = fetch_deps_for(card, api_key)
                    write_card_file(card, deps)
                    break
    else:
        say(tr['addons_none_confirmed'].format(name=target['title']))
    say(tr['commands'])

def do_help():
    tr = T[LANG]
    say(f"{GREEN}{BOLD}{tr['help_header']}{RESET}")
    for cmd, key in [
        ("key <ключ>", "help_key"), ("search <тег|name:название|ссылка ...>", "help_search"), ("show <N>", "help_show"),
        ("save <N>", "help_save"), ("saveall", "help_saveall"), ("bulk <тег|name:название|ссылка ...>", "help_bulk"),
        ("addons <slug|modid>", "help_addons"),
        ("build <ссылка|slug> [загрузчик] [версия] [client|server] [mr=N] [cf=N]", "help_build"),
        ("newaddons <ссылка|slug> [период] [загрузчик] [версия]", "help_newaddons"),
        ("importlink [prefer CF|M] [min mr=N cf=N]", "help_importlink"),
        ("update", "help_update"),
    ]:
        say()
        say("  " + BOLD + str(cmd) + RESET)
        say(f"      {tr[key]}")
    say()
    say("  " + BOLD + "slug" + RESET)
    say(f"      {tr['help_slug']}")

def load_cf_key():
    try:
        with open(CF_KEY_PATH, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                return line
    except OSError:
        return None
    return None

def save_cf_key(value):
    try:
        with open(CF_KEY_PATH, "w", encoding="utf-8") as f:
            f.write(CF_KEY_HEADER)
            f.write(value.strip() + "\n")
    except OSError:
        pass

def print_banner():
    tr = T[LANG]
    print("\n" * 30)
    print(GREEN + BOLD + "================================================" + RESET)
    print(GREEN + BOLD + tr['banner_title'] + RESET)
    print(GREEN + tr['banner_note'] + RESET)
    print(f"{GREEN}{BOLD}================================================{RESET}")
    print()
    print(tr["commands"])



def choose_language():
    global LANG
    while True:
        try:
            choice = input("Выберите язык / Choose language [ru/en]: ").strip().lower()
        except EOFError:
            LANG = "ru"
            return
        if choice in ("ru", "en"):
            LANG = choice
            return
        if not choice:
            LANG = "ru"
            return


MAIN_LIMIT = 150      #F31
SUB_ADDON_LIMIT = 30      #F32
MAX_DEPTH = 5         #F33
POSSIBLE_LIMIT = 40   #F34
DL_WORKERS = 4        #F35
LOADERS = ("forge", "neoforge", "fabric", "quilt")
LOADER_LABEL = {"forge": "Forge", "neoforge": "NeoForge", "fabric": "Fabric", "quilt": "Quilt"}
CF_LOADER_IDS = {"forge": 1, "fabric": 4, "quilt": 5, "neoforge": 6}
PACKS_DIR = os.path.join(OUTPUT_DIR, "modpacks")
ANSWERS_PATH = os.path.join(OUTPUT_DIR, ".build_answers.json")
REL_VER_RE = re.compile(r"^\d+\.\d+(\.\d+)?$")

def _vtup(v):
    t = tuple(int(x) for x in re.findall(r"\d+", v or ""))
    return (t + (0, 0, 0))[:3]

def _ask(prompt):
    try:
        return input(prompt).strip()
    except (EOFError, KeyboardInterrupt):
        say()
        return None

def _slug_of(ent):
    base = ""
    for side in ("mr", "cf"):
        if ent.get(side) and ent[side]["card"].get("slug"):
            base = ent[side]["card"]["slug"]
            break
    return re.sub(r"[^a-z0-9_-]+", "-", (base or ent["title"]).lower()).strip("-") or "mod"

def _qname(title):
    q = _ws(re.sub(r"[\(\[].*?[\)\]]", " ", title or ""))
    return q or (title or "")

#F36

def _norm_pres(label_map):
    out = {}
    for label, vers in (label_map or {}).items():
        name = str(label).lower()
        if name not in LOADERS:
            continue
        good = set(v for v in (vers or []) if REL_VER_RE.match(v or ""))
        if good:
            out.setdefault(name, set()).update(good)
    return out

def cf_presence(hit):
    out = {}
    for idx in hit.get("latestFilesIndexes") or []:
        gv = idx.get("gameVersion")
        if not REL_VER_RE.match(gv or ""):
            continue
        name = (CF_MODLOADER_NAME.get(idx.get("modLoader")) or "").lower()
        if not name and _vtup(gv) < (1, 14, 0):
            name = "forge"          #F37
        if name in LOADERS:
            out.setdefault(name, set()).add(gv)
    return out

def slim_cf_hit(h):
    links = h.get("links") or {}
    return {"id": h.get("id"), "slug": h.get("slug"), "name": h.get("name"), "summary": h.get("summary"),
            "downloadCount": h.get("downloadCount", 0), "classId": h.get("classId"),
            "links": {"websiteUrl": links.get("websiteUrl")},
            "categories": [{"name": c.get("name")} for c in (h.get("categories") or [])],
            "isClientOnly": h.get("isClientOnly") if isinstance(h.get("isClientOnly"), bool) else None,
            "isServerOnly": h.get("isServerOnly") if isinstance(h.get("isServerOnly"), bool) else None,
            "pres": dict((k, sorted(v)) for k, v in cf_presence(h).items()),
            "sha1": cf_sha1s(h)}

def mr_record(card):
    pid = card["id"]
    deps = modrinth_latest_version_deps(pid) or []
    pres = _norm_pres(modrinth_loader_versions(pid))
    edges = [(d[0], d[1]) for d in deps if len(d) >= 2 and d[1] and d[0] in ("required", "optional", "incompatible")]
    return {"side": "mr", "id": pid, "card": card, "pres": pres, "edges": edges, "linked": False, "name_match": False}


def cf_record(slim, api_key, with_deps=True):
    cid = slim.get('id')
    deps = (cf_latest_file_deps(cid, api_key) or []) if with_deps else []
    pres = dict((k, set(v)) for k, v in (slim.get('pres') or {}).items())
    edges = [(d[0], d[1]) for d in deps if len(d) >= 2 and d[1] and d[0] in ("required", "optional", "incompatible")]
    return {'side': "cf", 'id': cid, 'card': normalize_cf_hit(slim), 'pres': pres, 'edges': edges,
            'linked': False, 'name_match': False, 'hashes': list(slim.get('sha1') or [])}

#F38

def mr_bsearch(title, limit):
    pages = max(1, -(-limit // PAGE_SIZE))
    key = f"mr_bsearch_v1z:{title.lower()}:{pages}:{PAGE_SIZE}"
    cached = cache_get(key)
    if cached != "MISS":
        return cached
    hits, status = _mr_pages([["project_type:mod"]], "relevance", title, pages)
    slim = [dict((k, h.get(k)) for k in ("project_id", "slug", "title", "description", "downloads", "categories"))
            for h in mr_only_mods(hits)]
    if status == "ok":
        cache_set(key, slim)
    return slim


def cf_bsearch(title, api_key, limit):
    pages = max(1, -(-limit // PAGE_SIZE))
    key = f"cf_bsearch_v2x:{title.lower()}:{pages}:{PAGE_SIZE}"
    cached = cache_get(key)
    if cached != "MISS":
        return cached
    items, ok = [], True
    for p in range(pages):
        url = ("https://api.curseforge.com/v1/mods/search?gameId=432&classId={}&searchFilter={}"
               "&pageSize={}&index={}&sortField=2&sortOrder=desc").format(
                   CF_CLASS_ID_MODS, urllib.parse.quote(title), PAGE_SIZE, p * PAGE_SIZE)
        data = http_get_json(url, headers=cf_headers(api_key))
        if data is None:
            ok = False
            break
        page = data.get("data", [])
        items.extend(page)
        if len(page) < PAGE_SIZE:
            break
    slim = [slim_cf_hit(h) for h in cf_only_mods(items)]
    if ok:
        cache_set(key, slim)
    return slim


def mr_by_slug(slug):
    key = "mr_bslug_v1k:" + str(slug).lower()
    cached = cache_get(key)
    if cached != "MISS":
        return cached
    p = http_get_json("https://api.modrinth.com/v2/project/" + urllib.parse.quote(str(slug), safe=""))
    if not isinstance(p, dict):
        return None
    slim = dict((k, p.get(k)) for k in ("id", "slug", "title", "description", "downloads", "categories", "project_type", "client_side", "server_side"))
    cache_set(key, slim)
    return slim


def cf_by_slug(slug, api_key):
    key = "cf_bslug_v2v:" + str(slug).lower()
    cached = cache_get(key)
    if cached != "MISS":
        return cached
    data = http_get_json("https://api.curseforge.com/v1/mods/search?gameId=432&classId={}&slug={}".format(
        CF_CLASS_ID_MODS, urllib.parse.quote(str(slug))), headers=cf_headers(api_key))
    if data is None:
        return None
    items = cf_only_mods(data.get('data', []))
    slim = slim_cf_hit(items[0]) if items else None
    cache_set(key, slim)
    return slim

def other_on_cf(card, api_key):
    slim = cf_by_slug(card["slug"], api_key) if card.get("slug") else None
    if slim and _titles_similar(slim.get("name"), card.get("title")):
        return slim
    for h in cf_bsearch(_qname(card.get("title")), api_key, 10):
        if _titles_similar(h.get("name"), card.get("title")):
            return h
    return None


def other_on_mr(card):
    proj = mr_by_slug(card["slug"]) if card.get("slug") else None
    if proj and proj.get("project_type") in (None, "mod") and _titles_similar(proj.get("title"), card.get("title")):
        return card_from_mr_project(proj)
    for h in modrinth_search_text(_qname(card.get("title"))):
        if _titles_similar(h.get("title"), card.get("title")):
            return normalize_modrinth_hit(h)
    return None


def find_main_mod(target, api_key):
    slug, side = target, None
    if is_url(target):
        pu = urllib.parse.urlparse(target)
        parts = [p for p in pu.path.split("/") if p]
        if "modrinth.com" in pu.netloc.lower() and len(parts) >= 2:
            side, slug = "mr", parts[1]
        elif "curseforge.com" in pu.netloc.lower() and len(parts) >= 3:
            side, slug = "cf", parts[2]
        else:
            return None, None
    mr_card, cf_slim = None, None
    if side in (None, "mr"):
        p = mr_by_slug(slug)
        if p and p.get("project_type") in (None, "mod"):
            mr_card = card_from_mr_project(p)
    if api_key and (side == "cf" or (side is None and not mr_card)):
        cf_slim = cf_by_slug(slug, api_key)
        if not cf_slim and str(slug).isdigit():
            raw = cf_mod_by_id(slug, api_key)
            if raw and raw.get("classId") in (None, CF_CLASS_ID_MODS):
                cf_slim = slim_cf_hit(raw)
    if mr_card and not cf_slim and api_key:
        cf_slim = other_on_cf(mr_card, api_key)
    elif cf_slim and not mr_card:
        mr_card = mr_for_cf(normalize_cf_hit(cf_slim), cf_slim.get("sha1"))
    return mr_card, cf_slim

#F39

def new_world(title, mr_rec, cf_rec):
    main = {"n": 0, "title": title, "mr": None, "cf": None, "main": True, "edges": {}}
    W = {"ents": [main], "by_mr": {}, "by_cf": {}, "pool": [], "seen_mr": set(), "seen_cf": set(),
         "lock": threading.RLock()}
    for rec in (mr_rec, cf_rec):
        if rec:
            _reg(W, main, rec)
    return W


def _reg(W, ent, rec):
    ent[rec["side"]] = rec
    rec["linked"] = True
    W["by_" + rec["side"]][rec["id"]] = ent
    W["seen_" + rec["side"]].add(rec["id"])



def _entity_for(W, rec):
    with W["lock"]:
        card, side = rec["card"], rec["side"]
        for e in W["ents"]:
            if e.get(side):
                continue
            base = (e.get("mr") or e.get("cf"))["card"]
            same_slug = bool(card.get("slug")) and card["slug"].lower() == (base.get("slug") or "").lower()
            if (same_slug or norm_title(card.get("title")) == norm_title(base.get("title"))) \
                    and _titles_similar(base.get("title"), card.get("title")):
                _reg(W, e, rec)
                return e, False
        ent = {"n": len(W["ents"]), "title": card.get("title") or "?", "mr": None, "cf": None, "edges": {}}
        W["ents"].append(ent)
        _reg(W, ent, rec)
        return ent, True


def collect_addons(W, frontier, api_key, limit, opts):
    found_mr, found_cf = {}, {}
    lock=threading.Lock()

    def one(ent):
        title = _qname(ent['title'])
        nt = _blob(title)
        if len(nt) < 3:
            return
        mr_hits = mr_bsearch(title, limit)
        cf_hits = cf_bsearch(title, api_key, limit) if api_key else []
        with lock:
            for h in mr_hits:
                pid = h.get('project_id')
                if not pid or pid in W['seen_mr'] or pid in found_mr:
                    continue
                if (h.get('downloads') or 0) < opts['mr']:
                    continue
                if nt in _blob(h.get('title'), h.get('slug'), h.get('description')):
                    found_mr[pid] = h
            for h in cf_hits:
                cid = h.get('id')
                if not cid or cid in W['seen_cf'] or cid in found_cf:
                    continue
                if (h.get('downloadCount') or 0) < opts['cf']:
                    continue
                if nt in _blob(h.get('name'), h.get('slug'), h.get('summary')):
                    found_cf[cid] = h

    _parallel_map(one, frontier)
    W['seen_mr'].update(found_mr)
    W['seen_cf'].update(found_cf)
    return found_mr, found_cf


def verify_edges(W, found_mr, found_cf, api_key, main_nt):
    total = len(found_mr) + len(found_cf)
    prog = {"n": 0}
    lock = threading.Lock()

    def done(rec):
        with lock:
            W["pool"].append(rec)
            prog["n"] += 1
            if prog["n"] % 25 == 0:
                say(_t('проверено {}/{}', 'checked {}/{}').format(prog["n"], total))

    def one_mr(h):
        rec = mr_record(normalize_modrinth_hit(h))
        rec["name_match"] = main_nt in _blob(rec["card"].get("title"), rec["card"].get("slug"))
        done(rec)

    def one_cf(h):
        rec = cf_record(h, api_key)
        rec["name_match"] = main_nt in _blob(rec["card"].get("title"), rec["card"].get("slug"))
        done(rec)

    _parallel_map(one_mr, list(found_mr.values()))
    _parallel_map(one_cf, list(found_cf.values()))

def _link_pass(W):
    new_ents = []
    changed = True
    while changed:
        changed = False
        for rec in list(W["pool"]):
            if rec["linked"]:
                continue
            known = W["by_" + rec["side"]]
            if rec.get("force") or any(k in ("required", "optional") and t in known for k, t in rec["edges"]):
                ent, is_new = _entity_for(W, rec)
                changed = True
                if is_new:
                    new_ents.append(ent)
    return new_ents

def fill_other_side(W, ent, api_key, opts):
    if ent.get("mr") and ent.get("cf"):
        return
    if ent.get("mr"):
        if not api_key:
            return
        slim = other_on_cf(ent["mr"]["card"], api_key)
        if not slim:
            return
        if (slim.get("downloadCount") or 0) < opts["cf"] or slim["id"] in W["by_cf"]:
            return
        rec = cf_record(slim, api_key)
    else:
        card = mr_for_cf(ent["cf"]["card"], ent["cf"].get("hashes"))
        if not card or (card.get("downloads") or 0) < opts["mr"] or card["id"] in W["by_mr"]:
            return
        rec = mr_record(card)
    with W["lock"]:
        if not ent.get(rec["side"]) and rec["id"] not in W["by_" + rec["side"]]:
            _reg(W, ent, rec)

def link_all(W, api_key, opts):
    got = []
    while True:
        batch = _link_pass(W)
        if not batch:
            return got
        got.extend(batch)
        _parallel_map(lambda e: fill_other_side(W, e, api_key, opts), batch)


def analyze_world(W, api_key, opts, main_nt):
    frontier = [W["ents"][0]]
    depth = 0
    while frontier and depth < MAX_DEPTH:
        depth += 1
        limit=MAIN_LIMIT if depth == 1 else SUB_ADDON_LIMIT
        say(_t("Шаг {}: ищу аддоны, модов в проверке: {}...", "Step {}: looking for addons, mods to check: {}...").format(
            depth, len(frontier)))
        found_mr, found_cf = collect_addons(W, frontier, api_key, limit, opts)
        say(_t('кандидатов: {} (Modrinth {}, CurseForge {})', 'candidates: {} (Modrinth {}, CurseForge {})').format(
                    len(found_mr) + len(found_cf), len(found_mr), len(found_cf)))
        verify_edges(W, found_mr, found_cf, api_key, main_nt)
        frontier = link_all(W, api_key, opts)
        say(_t('аддонов на этом шаге: {}', 'addons at this step: {}').format(len(frontier)))
        save_cache()

#F40

def _ent_pres(ent):
    out = {}
    for side, tag in (("mr", "M"), ("cf", "CF")):
        rec = ent.get(side)
        if rec:
            for loader, vers in rec["pres"].items():
                for v in vers:
                    out.setdefault((loader, v), set()).add(tag)
    return out


def aggregate(W):
    main = W['ents'][0]
    for e in W['ents']:
        e['edges'] = {}
        e['pmap'] = _ent_pres(e)
        for side in ("mr", "cf"):
            rec = e.get(side)
            if not rec:
                continue
            known = W["by_" + side]
            for kind, tid in rec['edges']:
                t = known.get(tid)
                if t is None or t is e or kind not in ("required", "optional"):
                    continue
                if e['edges'].get(t['n']) != "required":
                    e['edges'][t['n']] = kind
        if e is not main and any((e.get(s) or {}).get('force') for s in ("mr", "cf")):
            e['edges'][main['n']] = "required"

def members_of(ents, main, key):
    #F71
    req, lnk = set([main['n']]), set([main['n']])
    cand = [e for e in ents if e is not main and key in e['pmap']]
    changed = True
    while changed:
        changed = False
        for e in cand:
            n = e['n']
            if n not in req and any(k == "required" and t in req for t, k in e['edges'].items()):
                req.add(n)
                lnk.add(n)
                changed = True
            elif n not in lnk and any(t in lnk for t in e['edges']):
                lnk.add(n)
                changed = True
    return req, lnk


def af_entity_side(ent):
    for side in ("mr", "cf"):
        rec = ent.get(side)
        card = (rec or {}).get("card") if isinstance(rec, dict) else None
        if not isinstance(card, dict):
            continue
        if side == "mr":
            client, server = card.get("client_side"), card.get("server_side")
            if server == "unsupported" and client in ("required", "optional"):
                return "client"
            if client == "unsupported" and server in ("required", "optional"):
                return "server"
        else:
            if card.get("isClientOnly") is True and card.get("isServerOnly") is not True:
                return "client"
            if card.get("isServerOnly") is True and card.get("isClientOnly") is not True:
                return "server"
    return "unknown"


def make_blocks(W, opts):
    ents, main = W["ents"], W["ents"][0]
    blocks = []
    wanted_side = opts.get("side")
    for key in sorted(main["pmap"]):
        if opts["loaders"] and key[0] not in opts["loaders"]:
            continue
        if opts["versions"] and key[1] not in opts["versions"]:
            continue
        req, lnk = members_of(ents, main, key)
        req_ents = [e for e in ents if e["n"] in req and e is not main]
        opt_ents = [e for e in ents if e["n"] in lnk and e["n"] not in req]
        blocked = []
        skipped_optional = []
        if wanted_side:
            main_side = af_entity_side(main)
            if main_side in ("client", "server") and main_side != wanted_side:
                blocked.append(main["title"] + " (main mod is " + main_side + "-only)")
            for e in req_ents:
                entity_side = af_entity_side(e)
                if entity_side in ("client", "server") and entity_side != wanted_side:
                    blocked.append(e["title"] + " (required dependency is " + entity_side + "-only)")
            opt_ents = [e for e in opt_ents if not (
                af_entity_side(e) in ("client", "server") and af_entity_side(e) != wanted_side)]
            skipped_optional = [e for e in ents if e["n"] in lnk and e["n"] not in req and e not in opt_ents]
        blocks.append({"key": key, "req": req_ents, "opt": opt_ents, "blocked": blocked,
                       "side_skipped": skipped_optional, "side": wanted_side or "both"})
    for loader in LOADERS:
        same = sorted([b for b in blocks if b["key"][0] == loader], key=lambda b: _vtup(b["key"][1]))
        vers = [b["key"][1] for b in same]
        where = {}
        for b in same:
            for e in b["req"] + b["opt"]:
                where.setdefault(e["n"], []).append(b["key"][1])
        for b in same:
            here = set(e["n"] for e in b["req"] + b["opt"])
            b["excl"], b["absent"] = set(), {}
            for e in b["req"] + b["opt"]:
                w = where[e["n"]]
                if len(vers) >= 2 and len(w) == 1:
                    b["excl"].add(e["n"])
                else:
                    b["absent"][e["n"]] = [v for v in vers if v not in w]
            b["elsewhere"] = [(ents[n], w) for n, w in where.items() if n not in here]
    blocks.sort(key=lambda b: (bool(b.get("blocked")), -len(b["req"]), tuple(-x for x in _vtup(b["key"][1])), b["key"][0]))
    return blocks

#F42

def answers_load():
    try:
        with open(ANSWERS_PATH, "r", encoding="utf-8") as f:
            d = json.load(f)
        return d if isinstance(d, dict) else {}
    except (OSError, ValueError):
        return {}


def answers_save(d):
    try:
        os.makedirs(OUTPUT_DIR, exist_ok=True)
        with open(ANSWERS_PATH, "w", encoding="utf-8") as f:
            json.dump(d, f, ensure_ascii=False, indent=1)
    except OSError:
        pass


def plat_tag(plats):
    if "M" in plats and "CF" in plats:
        return "[M x CF]"
    return "[M]" if "M" in plats else "[CF]"

def ask_possible(W, opts, api_key):
    main = W['ents'][0]
    keys = set(k for k in _ent_pres(main) if (not opts['loaders'] or k[0] in opts['loaders'])
               and (not opts['versions'] or k[1] in opts['versions']))
    cands = []
    for rec in W['pool']:
        if rec['linked'] or not rec['name_match']:
            continue
        if not any((lo, v) in keys for lo, vs in rec['pres'].items() for v in vs):
            continue
        title = rec['card'].get('title') or "?"
        for c in cands:
            if rec['side'] not in c['recs'] and _titles_similar(c['title'], title):
                c['recs'][rec['side']] = rec
                break
        else:
            cands.append({'title': title, 'key': norm_title(title), 'recs': {rec['side']: rec}})
    answers = answers_load()
    mine = answers.setdefault(norm_title(main['title']), {'yes': [], 'no': []})
    ask, forced = [], False
    for c in cands:
        if c['key'] in mine['yes']:
            for r in c['recs'].values():
                r['force'] = True
            forced = True
        elif c['key'] not in mine['no']:
            ask.append(c)
    ask.sort(key=lambda c: -sum((r['card'].get('downloads') or 0) for r in c['recs'].values()))
    ask = ask[:POSSIBLE_LIMIT]
    if ask:
        say()
        say(f"{GREEN}{BOLD}" + _t("=== Возможные аддоны: название похоже, а зависимости на '{}' нет ===", "=== Possible addons: similar name but no dependency on '{}' ===").format(
                                   main['title']) + RESET)
        for i, c in enumerate(ask, 1):
            tags = plat_tag(set({'mr': "M", 'cf': "CF"}[s] for s in c['recs']))
            links = " | ".join(r['card'].get('link') or "" for r in c['recs'].values())
            say("{}) {} {}  {}".format(i, c['title'], tags, links))
        ans = _ask(_t("Это аддон к '{}'? Номера через пробел (a = все, Enter = нет):", "Is this an addon of '{}'? Enter numbers separated by spaces (a = all, Enter = no):").format(
                                 main['title']))
        if ans is not None:
            pick = set()
            for tok in ans.replace(",", " ").split():
                if tok.lower() in ("a", "all", "все"):
                    pick = set(range(1, len(ask) + 1))
                elif tok.isdigit() and 1 <= int(tok) <= len(ask):
                    pick.add(int(tok))
            for i, c in enumerate(ask, 1):
                if i in pick:
                    mine['yes'].append(c['key'])
                    for r in c['recs'].values():
                        r['force'] = True
                    forced = True
                else:
                    mine['no'].append(c['key'])
            answers_save(answers)
    if forced:
        link_all(W, api_key, opts)



#F43

def dl_count(e):
    return sum((e[s]["card"].get("downloads") or 0) for s in ("mr", "cf") if e.get(s))


def sorted_by_dl(lst, b):
    return sorted(lst, key=lambda e: (e['n'] not in b['excl'], -dl_count(e), e['title'].lower()))

def block_head(b):
    s = _t("{} {} - найдено аддонов: {}", "{} {} - addons found: {}").format(
        LOADER_LABEL[b["key"][0]], b["key"][1], len(b["req"]))
    if b["opt"]:
        s += _t(' (+{} необязательных)', " (+{} optional)").format(len(b["opt"]))
    if b.get("side") in ("client", "server"):
        s += " [" + b["side"].upper() + "]"
    if b.get("blocked"):
        s += _t(' [НЕСОВМЕСТИМА]', " [BLOCKED]")
    return s

def block_line(e, b, links, cut):
    s = e['title'] + " " + plat_tag(e['pmap'].get(b['key'], set()))
    if e['n'] in b['excl']:
        s="exclusive " + s
    elif b['absent'].get(e['n']):
        a = b['absent'][e['n']]
        if cut and len(a) > cut:
            a = a[:cut] + ["..."]
        s += _t(" (нет на: ", " (missing on: ") + ", ".join(a) + ")"
    if links:
        urls = [e[s2]['card'].get('link') for s2 in ("mr", "cf") if e.get(s2) and e[s2]['card'].get('link')]
        s += "  " + " | ".join(urls)
        if any((e.get(s2) or {}).get('force') for s2 in ("mr", "cf")):
            s += _t('    (подтверждён вручную)', "  (confirmed by hand)")
    return s


def print_blocks(main, blocks):
    say()
    say(f"{GREEN}{BOLD}" + _t("=== Сборки для мода: {} ===", "=== Builds for mod: {} ===").format(main["title"]) + RESET)
    for i, b in enumerate(blocks, 1):
        say(BOLD + f"[{i}] {block_head(b)}" + RESET)
        for reason in b.get("blocked", []):
            say(f"  {RED}{reason}{RESET}")
        for e in sorted_by_dl(b["req"], b):
            say("  " + block_line(e, b, False, 6))
        if b["opt"]:
            say("  " + _t("необязательные:", "optional:"))
            for e in sorted_by_dl(b["opt"], b):
                say("    " + block_line(e, b, False, 6))
    say()
    say(GREEN + BOLD + _t("=== Итог: сборки по числу аддонов ===", "=== Total: builds by number of addons ===") + RESET)
    for i, b in enumerate(blocks, 1):
        say(" {}) {}".format(i, block_head(b)))


def write_reports(main, blocks):
    slug = _slug_of(main)
    stamp = time.strftime("%Y-%m-%d %H:%M")
    lines = [_t("Сборки для мода: {} | обновлено {}", "Builds for mod: {} | updated {}").format(main['title'], stamp), ""]
    ai = [f"# build for {main['title']} | {stamp} | M=Modrinth CF=CurseForge x:=exclusive opt=optional addons"]
    for b in blocks:
        lines.append(block_head(b))
        for e in sorted_by_dl(b['req'], b):
            lines.append("  " + block_line(e, b, True, 0))
        if b['opt']:
            lines.append("  " + _t("Необязательные:", "Optional:"))
            for e in sorted_by_dl(b['opt'], b):
                lines.append("    " + block_line(e, b, True, 0))
        if b['elsewhere']:
            lines.append("  " + _t("Нет в этой сборке, но есть на других версиях ({}):", "Not in this build but exist on other versions ({}):").format(len(b['elsewhere'])))
            for e, w in sorted(b['elsewhere'], key=lambda x: x[0]['title'].lower()):
                lines.append(f"    {e['title']} ({', '.join(w)})")
        lines.append("")

        def names(lst):
            out = []
            for e in sorted_by_dl(lst, b):
                t = "+".join({'M': "M", 'CF': "CF"}[x] for x in sorted(e['pmap'].get(b['key'], set()), reverse=True))
                out.append(("x:" if e['n'] in b['excl'] else "") + e['title'] + "[" + t + "]")
            return "; ".join(out)
        row = f"{b['key'][0]} {b['key'][1]} n={len(b['req'])}: {names(b['req'])}"
        if b['opt']:
            row += " | opt: " + names(b['opt'])
        ai.append(row)
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    paths = (os.path.join(OUTPUT_DIR, "build_{}.txt".format(slug)), os.path.join(OUTPUT_DIR, "build_{}_ai.txt".format(slug)))
    for path, text in zip(paths, ("\n".join(lines), "\n".join(ai))):
        with open(path, "w", encoding="utf-8") as f:
            f.write(text + "\n")
    return paths

#F44

def mr_pick(pid, loader, ver):
    key = f"mr_pick_v2k:{pid}:{loader}:{ver}"
    cached = cache_get(key)
    if cached != "MISS":
        return cached
    url = ("https://api.modrinth.com/v2/project/{}/version?loaders={}&game_versions={}").format(
        pid, urllib.parse.quote(json.dumps([loader])), urllib.parse.quote(json.dumps([ver])))
    data = http_get_json(url)
    if not isinstance(data, list):
        return None
    vs = [v for v in data if isinstance(v, dict) and v.get("files")]
    vs.sort(key=lambda v: v.get("date_published") or "", reverse=True)
    vs.sort(key=lambda v: {"release": 0, "beta": 1, "alpha": 2}.get(v.get("version_type"), 3))
    result = None
    if vs:
        v = vs[0]
        f = next((x for x in v["files"] if x.get("primary")), v["files"][0])
        result = {"url": f.get("url"), "filename": f.get("filename"), "vtype": v.get("version_type") or "?",
                  "host": "modrinth", "sha1": (f.get("hashes") or {}).get("sha1"),
                  "sha512": (f.get("hashes") or {}).get("sha512"), "size": f.get("size"),
                  "version": v.get("version_number") or v.get("name") or "?",
                  "deps": [[d.get("dependency_type"), d.get("project_id")] for d in (v.get("dependencies") or [])
                           if d.get("project_id")]}
    cache_set(key, result)
    return result

def cf_pick(mid, loader, ver, api_key):
    key = f"cf_pick_v2y:{mid}:{loader}:{ver}"
    cached=cache_get(key)
    if cached != "MISS":
        return cached
    base = f"https://api.curseforge.com/v1/mods/{mid}/files?gameVersion={urllib.parse.quote(ver)}&pageSize=50"
    data = http_get_json(base + f"&modLoaderType={CF_LOADER_IDS[loader]}", headers=cf_headers(api_key))
    if data == None:
        return None
    files=data.get("data") or []
    if not files and loader == "forge" and _vtup(ver) < (1, 14, 0):
        files = (http_get_json(base, headers=cf_headers(api_key)) or {}).get("data") or []
    files = [f for f in files if isinstance(f, dict) and f.get("isAvailable", True)]
    files.sort(key=lambda f: f.get("fileDate") or "", reverse=True)
    files.sort(key=lambda f: f.get("releaseType") or 9)
    result = None
    if files:
        f = files[0]
        result = {"url": f.get("downloadUrl"), "filename": f.get("fileName"),
                  "vtype": {1: "release", 2: "beta", 3: "alpha"}.get(f.get("releaseType"), "?"),
                  "version": f.get("displayName") or f.get("fileName") or "?",
                  "deps": [[CF_RELATION_TYPE.get(d.get("relationType"), "embedded"), d.get("modId")]
                           for d in (f.get("dependencies") or []) if d.get("modId")]}
        result["host"] = "curseforge"
        result["sha1"] = cf_file_sha1(f)
        if not result["url"] and HASH_MATCH:
            via_modrinth(result)
    cache_set(key, result)
    return result


def pick_file(side, tid, loader, ver, api_key):
    return mr_pick(tid, loader, ver) if side == "mr" else cf_pick(tid, loader, ver, api_key)

def dep_card(side, tid, api_key):
    if side == "mr":
        p = mr_by_slug(tid)
        return card_from_mr_project(p) if p else None
    m = cf_mod_by_id(tid, api_key) if api_key else None
    return normalize_cf_hit(m) if m else None

def ent_links(ent):
    return [ent[s]["card"]["link"] for s in ("mr", "cf") if ent.get(s) and ent[s]["card"].get("link")]

def resolve_items(W, sel, loader, ver, api_key):
    items, missing, libs, req_by = [], [], [], {}
    lock = threading.Lock()
    sel_n = set(e['n'] for e in sel)
    done_titles = set(norm_title(e['title']) for e in sel) 

    def want_libs(pick, side, who):
        for kind, tid in pick.get('deps', []):
            if kind != "required" or not tid:
                continue
            ent = W["by_" + side].get(tid)
            if ent is not None and ent['n'] in sel_n:
                continue
            libs.append((side, tid, who))

    def one(e):
        tags = e['pmap'].get((loader, ver), set())
        pick, used = None, None
        for s, t in (("mr", "M"), ("cf", "CF")):
            if not e.get(s) or t not in tags:
                continue
            p = pick_file(s, e[s]['id'], loader, ver, api_key)
            if p and (p.get('url') or pick is None):
                pick, used = p, s
                if p.get('url'):
                    break
        with lock:
            if not pick:
                missing.append({'title': e['title'], 'links': ent_links(e), 'who': ""})
                return
            items.append({'title': e['title'], 'side': used, 'id': e[used]['id'], 'pick': pick, 'ents': e, 'lib': False})
            want_libs(pick, used, e['title'])

    def one_lib(x):
        side, tid, who = x
        card = dep_card(side, tid, api_key)
        if card is None:
            with lock:
                missing.append({'title': f"{side}:{tid}", 'links': [], 'who': who})
            return
        nt = norm_title(card.get('title'))
        with lock:
            req_by.setdefault(nt, set()).add(who)
            if nt in done_titles:
                return
            done_titles.add(nt)
        pick, used, ucard = pick_file(side, tid, loader, ver, api_key), side, card
        if not pick or not pick.get('url'):
            other = None
            if card['source'] == "Modrinth" and api_key:
                hit = other_on_cf(card, api_key)
                other = normalize_cf_hit(hit) if hit else None
            elif card['source'] != "Modrinth":
                other = other_on_mr(card)
            if other:
                s2 = "mr" if other['source'] == "Modrinth" else "cf"
                p2 = pick_file(s2, other['id'], loader, ver, api_key)
                if p2 and (p2.get('url') or not pick):
                    pick, used, ucard = p2, s2, other
        with lock:
            if not pick:
                missing.append({'title': card.get('title') or "?", 'links': [card.get('link')], 'who': who})
                return
            items.append({'title': ucard.get('title') or "?", 'side': used, 'id': ucard['id'], 'pick': pick,
                          'ents': None, 'lib': True, 'who': who, 'whos': req_by[nt]})
            want_libs(pick, used, ucard.get('title') or "?")

    _parallel_map(one, sel)
    seen_lib, level = set(), 0
    while libs and level < 8:
        level += 1
        batch, libs = libs, []
        batch = [x for x in batch if (x[0], x[1]) not in seen_lib]
        seen_lib.update((x[0], x[1]) for x in batch)
        _parallel_map(one_lib, batch)
    return items, missing

def ask_conflicts(items):
    idx={}
    for it in items:
        idx[(it['side'], it['id'])] = it
        if it.get('ents'):
            for s in ("mr", "cf"):
                if it['ents'].get(s):
                    idx[(s, it['ents'][s]['id'])] = it
    pairs, seen = [], set()
    for it in items:
        for kind, tid in it['pick'].get('deps', []):
            other = idx.get((it['side'], tid)) if kind == "incompatible" else None
            if other is not None and other is not it and frozenset((id(it), id(other))) not in seen:
                seen.add(frozenset((id(it), id(other))))
                pairs.append((it, other))
    alive = set(id(x) for x in items)
    for a, b in pairs:
        if id(a) not in alive or id(b) not in alive:
            continue
        say(YELLOW + _t("Конфликт: '{}' и '{}' объявлены несовместимыми.", "Conflict: '{}' and '{}' are marked incompatible.").format(a['title'], b['title']) + RESET)
        ans = _ask(_t('Убрать: 1 = {}, 2 = {}, Enter = оставить оба:', 'Remove: 1 = {}, 2 = {}, Enter keeps both:').format(a['title'], b['title']))
        victim = a if ans == "1" else b if ans == "2" else None
        if victim is None:
            continue
        if victim.get('ents') is not None and victim['ents'].get('main'):
            say("  " + _t("Главный мод убирать нельзя.", "Can't remove the main mod."))
            continue
        alive.discard(id(victim))
    changed = len(alive) < len(items)
    while changed:      #F45
        changed = False
        names = set(x['title'] for x in items if id(x) in alive)
        for x in items:
            if id(x) in alive and x['lib'] and not (x['whos'] & names):
                alive.discard(id(x))
                changed = True
    return [x for x in items if id(x) in alive]


def _fname(it):
    fn = re.sub(r'[\\/:*?"<>|]+', "_", os.path.basename(it['pick'].get('filename') or "")).strip()
    return fn or (re.sub(r"[^A-Za-z0-9._-]+", "_", it['title']) + ".jar")

#F69

def fmt_size(n):
    for u in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return "%d%s" % (n, u)
        n //= 1024
    return "%dTB" % n


def http_download(url, dest):
    tmp = dest + ".part"
    for attempt in range(3):
        if _CANCEL.is_set():
            break
        try:
            req = urllib.request.Request(url, headers={'User-Agent': "auto-modpacker"})
            with urllib.request.urlopen(req, timeout=60) as resp, open(tmp, "wb") as out:
                while True:
                    chunk = resp.read(65536)
                    if not chunk:
                        break
                    out.write(chunk)
            os.replace(tmp, dest)
            return True
        except Exception:
            time.sleep(1 + attempt)
    try:
        os.remove(tmp)
    except OSError:
        pass
    return False

def download_all(items, mods_dir):
    ok, bad, manual, todo = [], [], [], []
    for it in items:
        if it["pick"].get("url"):
            todo.append((it, os.path.join(mods_dir, _fname(it))))
        else:
            manual.append(it)
    lock = threading.Lock()
    prog = {"n": 0}

    def one(x):
        it, dest = x
        good = (os.path.exists(dest) and os.path.getsize(dest) > 0) or http_download(it["pick"]["url"], dest)
        with lock:
            (ok if good else bad).append(it)
            prog["n"] += 1
            if prog["n"] % 10 == 0:
                say(_t('скачано {}/{}', 'downloaded {}/{}').format(prog["n"], len(todo)))

    _parallel_map(one, todo, workers=DL_WORKERS)
    return ok, bad, manual

def item_links(it):
    if it.get("ents"):
        return ent_links(it["ents"])
    return [it.get("link")] if it.get("link") else []

def make_pack(W, b, api_key):
    main = W["ents"][0]
    loader, ver = b["key"]
    if b.get("blocked"):
        say(f"{RED}{_t('Сборка остановлена: обязательные моды несовместимы с выбранной стороной.', 'Build stopped: required mods are incompatible with the selected side.')}{RESET}")
        for reason in b["blocked"]:
            say("  " + reason)
        return
    sel = [main] + list(b["req"])
    say()
    say(_t("Собираю список файлов для {} {}, модов в сборке {}...", "Collecting files for {} {} (mods in the build: {})...").format(LOADER_LABEL[loader], ver, len(sel)))
    folder = os.path.join(PACKS_DIR, "{}_{}_{}".format(_slug_of(main), loader, ver))
    mods_dir = os.path.join(folder, "mods")
    try:
        items, missing = resolve_items(W, sel, loader, ver, api_key)
        if missing:
            say(f"{YELLOW}{_t('Предварительная проверка: не найден файл под выбранную версию/загрузчик для:', 'Preflight: no file found for the selected version/loader for:')}{RESET}")
            for entry in missing:
                say("  " + entry.get("title", "?") + (" — " + str(entry.get("who")) if entry.get("who") else ""))
            answer = _ask(_t('Продолжить частичную сборку? [y/N]:', 'Continue with a partial build? [y/N]:'))
            if answer is None or answer.strip().lower() not in ("y", "yes", "д", "да"):
                say(_t("Сборка отменена после предварительной проверки.", "Build cancelled after preflight."))
                return
        items = ask_conflicts(items)
        os.makedirs(mods_dir, exist_ok=True)
        say(_t("Скачиваю {} файл(ов) в {} ...", "Downloading {} file(s) to {} ...").format(
            sum(1 for it in items if it["pick"].get("url")), mods_dir))
        ok, bad, manual = download_all(items, mods_dir)
    except KeyboardInterrupt:
        _CANCEL.clear()
        say(f"{YELLOW}{_t('Прервано, модпак не завершён.', 'Interrupted, modpack is not finished.')}{RESET}")
        return
    lines = [_t("Модпак: {} | {} {} | {}", "Modpack: {} | {} {} | {}").format(
        main["title"], LOADER_LABEL[loader], ver, time.strftime("%Y-%m-%d %H:%M")), ""]
    lines.append(_t("Скачано ({}):", "Downloaded ({}):").format(len(ok)))
    for it in sorted(ok, key=lambda x: x["title"].lower()):
        lines.append("  {} | {} | {} | {}{}{}".format(
            it["title"], "Modrinth" if (it["side"] == "mr" or it["pick"].get("via")) else "CurseForge", it["pick"].get("version"),
            _fname(it), "" if it["pick"].get("vtype") == "release" else " | " + str(it["pick"].get("vtype")),
            _t(" | библиотека для: ", " | library for: ") + it.get("who", "") if it["lib"] else ""))
    problems = []
    for title, lst in ((_t("Скачать вручную (автор запретил автоскачивание)", "Download manually (author disabled it)"), manual),
                       (_t("Не удалось скачать", "Download failed"), bad)):
        if lst:
            problems.append((title, [(it["title"], item_links(it)) for it in lst]))
    if missing:
        problems.append((_t("Нет файла под эту версию/загрузчик", "No file for this version/loader"),
                         [(m["title"] + (" (" + m["who"] + ")" if m.get("who") else ""), m["links"]) for m in missing]))
    for title, lst in problems:
        lines.append("")
        lines.append(f"{title} ({len(lst)}):")
        for name, links in lst:
            lines.append(f"  {name}  {' | '.join(x for x in links if x)}")
    with open(os.path.join(folder, "modpack.txt"), "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    say(GREEN + BOLD + _t("Готово: скачано {} из {}, библиотек среди них {}.", "Done: {} of {} downloaded (libraries: {}).").format(
        len(ok), len(ok) + len(bad), sum(1 for it in ok if it["lib"])) + RESET)
    for title, lst in problems:
        say(YELLOW + "{} ({}):".format(title, len(lst)) + RESET)
        for name, links in lst:
            say("  {}  {}".format(name, " | ".join(x for x in links if x)))
    say(_t("Папка: {}  (список: modpack.txt)", "Folder: {}  (list: modpack.txt)").format(folder))
    after_pack(main, loader, ver, ok, mods_dir, folder)



#F46

def parse_build_args(args):
    opts = {"target": None, "loaders": [], "versions": [], "mr": 0, "cf": 0, "side": None}
    rest = []
    for a in args:
        low = {"neo": "neoforge"}.get(a.lower(), a.lower())
        m = re.match(r"^(mr|cf)=(\d+)([km]?)$", low)
        if m:
            opts[m.group(1)] = int(m.group(2)) * {"": 1, "k": 1000, "m": 1000000}[m.group(3)]
        elif low in LOADERS:
            if low not in opts["loaders"]:
                opts["loaders"].append(low)
        elif low in ("client", "server"):
            opts["side"] = low
        elif REL_VER_RE.match(a):
            opts["versions"].append(a)
        else:
            rest.append(a)
    opts["target"] = rest[0] if rest else args[0]
    for a in rest[1:]:
        say(YELLOW + _t("Неизвестный параметр '{}', пропускаю.", "Don't know option '{}', skipping.").format(a) + RESET)
    return opts


def do_build(args, api_key):
    tr = T[LANG]
    if not args:
        say(_t("Использование: build <ссылка|slug> [forge|neoforge|fabric|quilt] [версия ...] [client|server] [mr=N] [cf=N]",
                "Usage: build <link|slug> [forge|neoforge|fabric|quilt] [version ...] [client|server] [mr=N] [cf=N]"))
        return
    if not check_internet():
        say(f"{RED}{tr['no_internet']}{RESET}")
        return
    _CANCEL.clear()
    opts = parse_build_args(args)
    default_loader = str(globals().get("_AUDIT_API_LOADER") or "").lower()
    default_version = str(globals().get("_AUDIT_TARGET_MC") or "")
    if REL_VER_RE.match(default_version):
        if not opts["loaders"] and default_loader in LOADERS:
            opts["loaders"] = [default_loader]
        if not opts["versions"]:
            opts["versions"] = [default_version]
    if not api_key:
        say(f"{YELLOW}{tr['search_cf_skipped']}{RESET}")
    say(_t("Ищу главный мод...", "Looking for the main mod..."))
    mr_card, cf_slim = find_main_mod(opts['target'], api_key)
    if not mr_card and not cf_slim:
        say(f"{RED}{T[LANG]['mod_not_found']}{RESET}")
        return
    title = (mr_card or normalize_cf_hit(cf_slim))['title']
    W = new_world(title, mr_record(mr_card) if mr_card else None,
                         cf_record(cf_slim, api_key, with_deps=False) if cf_slim else None)
    say(_t("Главный мод: {} ({}).", "Main mod: {} ({}).").format(
        title, " + ".join(n for n, c in (("Modrinth", mr_card), ("CurseForge", cf_slim)) if c)))
    try:
        analyze_world(W, api_key, opts, _blob(_qname(title)))
        ask_possible(W, opts, api_key)
    except KeyboardInterrupt:
        say()
        say(f"{YELLOW}{tr['bulk_interrupted']}{RESET}")
    _CANCEL.clear()
    save_cache()
    aggregate(W)
    blocks = make_blocks(W, opts)
    if not blocks:
        say(_t("У главного мода нет версий под выбранные загрузчики/версии.", "Main mod has no versions for the chosen loaders/versions."))
        return
    print_blocks(W['ents'][0], blocks)
    try:
        paths = write_reports(W['ents'][0], blocks)
        say(_t("Отчёты: {} (для чтения), {} (сжато, для нейронки)", "Reports: {} (to read), {} (compact, for LLM)").format(
            os.path.relpath(paths[0], SCRIPT_DIR), os.path.relpath(paths[1], SCRIPT_DIR)))
    except OSError as e:
        say(tr['save_error'].format(err=e))
    while True:
        ans = _ask(_t("Создать модпак? Номер сборки из списка (Enter = нет): ", "Make a modpack? Build number from the list (Enter = no): "))
        if not ans or not ans.isdigit() or not (1 <= int(ans) <= len(blocks)):
            break
        make_pack(W, blocks[int(ans) - 1], api_key)
        save_cache()
    say(tr['commands'])


HASH_MATCH = True     #F47
AUTO_MRPACK = True    #F48
LOADER_DEP = {"forge": "forge", "neoforge": "neoforge", "fabric": "fabric-loader", "quilt": "quilt-loader"}


def cf_file_sha1(f):
    for h in f.get("hashes") or []:
        if h.get("algo") == 1 and h.get("value"):
            return str(h["value"]).lower()
    return None


def cf_sha1s(hit):
    out = []
    for f in (hit.get('latestFiles') or [])[:20]:
        s = cf_file_sha1(f)
        if s and s not in out:
            out.append(s)
    return out

def http_post_json(url, body, extra=None):
    host = urllib.parse.urlparse(url).netloc
    data = json.dumps(body).encode("utf-8")
    for attempt in range(3):
        if _CANCEL.is_set():
            return None
        with _HTTP_LOCK:
            wait = 0.22 - (time.time() - _LAST_REQ.get(host, 0))
            if wait > 0:
                time.sleep(wait)
            _LAST_REQ[host] = time.time()
        try:
            req = urllib.request.Request(url, data=data, method="POST",
                                         headers=dict({"User-Agent": "auto-modpacker", "Content-Type": "application/json"}, **(extra or {})))
            with urllib.request.urlopen(req, timeout=30) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            if e.code in (429, 500, 502, 503, 504) and attempt < 2:
                _CANCEL.wait(2 ** (attempt + 1))
                continue
            return None
        except (urllib.error.URLError, TimeoutError, ValueError, OSError):
            time.sleep(1 + attempt)
    return None

def mr_hash_lookup(hashes):
    out, need = {}, []
    for h in hashes or []:
        cached = cache_get("mr_hash_v1c:" + h)
        if cached == "MISS":
            need.append(h)
        elif cached:
            out[h] = cached
    for i in range(0, len(need), 100):
        chunk = need[i:i + 100]
        data = http_post_json("https://api.modrinth.com/v2/version_files", {'hashes': chunk, 'algorithm': "sha1"})
        if not isinstance(data, dict):
            continue
        for h in chunk:
            v, info = data.get(h), None
            if isinstance(v, dict) and v.get('project_id'):
                f = next((x for x in (v.get('files') or []) if str((x.get('hashes') or {}).get('sha1')).lower() == h), None)
                if f:
                    info = {'pid': v['project_id'], 'url': f.get('url'), 'filename': f.get('filename'), 'sha1': h,
                            'sha512': (f.get('hashes') or {}).get('sha512'), 'size': f.get('size')}
            cache_set("mr_hash_v1c:" + h, info)
            if info:
                out[h] = info
    return out


def mr_for_cf(card, hashes):
    if HASH_MATCH and hashes:
        pids = [i['pid'] for i in mr_hash_lookup(hashes).values()]
        if pids:
            p = mr_by_slug(max(set(pids), key=pids.count))
            if p and p.get('project_type') in (None, "mod"):
                return card_from_mr_project(p)
    return other_on_mr(card)

def via_modrinth(res):
    sha1 = res.get("sha1")
    info = mr_hash_lookup([sha1]).get(sha1) if sha1 else None
    if info and info.get("url"):
        res.update({"url": info["url"], "filename": info.get("filename") or res.get("filename"), "host": "modrinth",
                    "sha1": info["sha1"], "sha512": info.get("sha512"), "size": info.get("size"), "via": "modrinth"})


def loader_version(loader, mc):
    key = "loader_ver_v1:{}:{}".format(loader, mc)
    cached = cache_get(key, ttl=24 * 3600)
    if cached != "MISS" and cached:
        return cached
    ver = None
    if loader in ("fabric", "quilt"):
        base = "https://meta.fabricmc.net/v2" if loader == "fabric" else "https://meta.quiltmc.org/v3"
        data = http_get_json(f"{base}/versions/loader/{urllib.parse.quote(mc)}")
        vs = []
        if isinstance(data, list):
            vs = [x["loader"]["version"] for x in data if isinstance(x, dict) and (x.get("loader") or {}).get("version")]
        ver = next((v for v in vs if "beta" not in v and "pre" not in v), vs[0] if vs else None)
    elif loader == "forge":
        data = http_get_json("https://files.minecraftforge.net/net/minecraftforge/forge/promotions_slim.json")
        promos = (data or {}).get("promos") or {}
        ver = promos.get(mc + "-recommended") or promos.get(mc + "-latest")
    elif loader == "neoforge":
        data = http_get_json("https://maven.neoforged.net/api/maven/versions/releases/net/neoforged/neoforge")
        parts = mc.split(".")
        if _vtup(mc)[0] >= 26:      #F49
            prefix = ".".join((parts + ["0", "0"])[:3]) + "."
        else:                           #F50
            prefix = ".".join((parts[1:] + ["0"])[:2]) + "."
        vs = [v for v in ((data or {}).get("versions") or []) if str(v).startswith(prefix)]
        pool = [v for v in vs if "-" not in v] or vs
        ver = max(pool, key=lambda v: tuple(int(x) for x in re.findall(r"\d+", v))) if pool else None
    if ver:
        cache_set(key, ver)
    return ver

def export_mrpack(main, loader, ver, ok, mods_dir, folder):
    seen2 = set()
    lv = loader_version(loader, ver)
    if not lv:
        lv = _ask(_t("Не удалось определить версию {} для Minecraft {}. Введите вручную (Enter = пропустить .mrpack): ", "Can't detect the {} version for Minecraft {}. Type it manually (Enter = skip .mrpack): ").format(
                                LOADER_LABEL[loader], ver))
    if not lv:
        say(_t(".mrpack пропущен.", ".mrpack skipped."))
        return None
    files, bundled = [], []
    for it in sorted(ok, key=lambda x: x['title'].lower()):
        p, fn = it['pick'], _fname(it)
        if p.get('host') == "modrinth" and p.get('sha1') and p.get('sha512') and p.get('size') and p.get('url'):
            files.append({'path': "mods/" + fn, 'hashes': {'sha1': p['sha1'], 'sha512': p['sha512']},
                          'downloads': [p['url']], 'fileSize': p['size']})
        elif os.path.isfile(os.path.join(mods_dir, fn)):
            bundled.append(fn)
    index = {'formatVersion': 1, 'game': "minecraft", 'versionId': time.strftime("%Y.%m.%d.%H%M"),
             'name': "{} ({} {})".format(main['title'], LOADER_LABEL[loader], ver),
             'summary': _t("Собрано автоматически: главный мод + аддоны + библиотеки",
                            "Built automatically: main mod + addons + libraries"),
             'files': files, 'dependencies': {'minecraft': ver, LOADER_DEP[loader]: lv}}
    path = os.path.join(folder, "{}_{}_{}.mrpack".format(_slug_of(main), loader, ver))
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("modrinth.index.json", json.dumps(index, ensure_ascii=False, indent=2))
        for fn in bundled:
            z.write(os.path.join(mods_dir, fn), "overrides/mods/" + fn)
    say(GREEN + BOLD + _t(".mrpack готов: {}", ".mrpack ready: {}").format(path) + RESET)
    say(_t('загрузчик {} {}; по ссылкам Modrinth: {}, внутри архива (overrides/mods): {}',
            'loader {} {}; via Modrinth links: {}, inside the archive (overrides/mods): {}').format(
                LOADER_LABEL[loader], lv, len(files), len(bundled)))
    return path


def after_pack(main, loader, ver, ok, mods_dir, folder):
    via = [it["title"] for it in ok if it["pick"].get("via")]
    if via:
        say(YELLOW + _t("С Modrinth по хешу взяты файлы, которые не скачать с CurseForge ({}): {}", "Took from Modrinth by hash what CurseForge does not allow to download ({}): {}").format(
                             len(via), ", ".join(via)) + RESET)
        try:
            with open(os.path.join(folder, "modpack.txt"), "a", encoding="utf-8") as f:
                f.write("\n" + _t("С Modrinth по хешу файла CurseForge ({}): {}",
                                   "From Modrinth by CurseForge file hash ({}): {}").format(len(via), ", ".join(via)) + "\n")
        except OSError:
            pass
    if AUTO_MRPACK and ok:
        try:
            export_mrpack(main, loader, ver, ok, mods_dir, folder)
        except KeyboardInterrupt:
            _CANCEL.clear()
            say(f"{YELLOW}{_t('Прервано, .mrpack не создан.', 'Interrupted, .mrpack not created.')}" + RESET)
        except Exception as e:
            say(YELLOW + _t(".mrpack не создан: {}", ".mrpack not created: {}").format(e) + RESET)


SETTINGS_PATH = os.path.join(SCRIPT_DIR, ".importlink_settings.json")  #F8
MANIFEST_NAME = ".importlink.json"     #F51
IMPORT_WORKERS = 4                       #F52
READY_LINES = 8                   #F53
BAR_WIDTH = 24
FILES_CACHE_TTL = 3600                  #F54
SETTINGS_DEFAULTS = {"version": "", "loader": "", "prefer": "auto", "strict": False, "min_mr": 0, "min_cf": 0, "deps": True, "releases": False}
_NUM_RE = re.compile(r"\d+(?:\.\d+)*")
_URL_RE = re.compile(r"https?://[^\s<>\"']+")
_REL_RANK = {"release": 0, "beta": 1, "alpha": 2}


#F55


def load_settings():
    s = dict(SETTINGS_DEFAULTS)
    try:
        with open(SETTINGS_PATH, "r", encoding="utf-8") as f:
            d = json.load(f)
        if isinstance(d, dict):
            s.update(dict((k, d[k]) for k in SETTINGS_DEFAULTS if k in d))
    except (OSError, ValueError):
        pass
    return s



def save_settings(s):
    try:
        with open(SETTINGS_PATH, "w", encoding="utf-8") as f:
            json.dump(s, f, ensure_ascii=False)
    except OSError:
        pass


def show_settings(s):
    return _t("версия {} | загрузчик {} | prefer {}{} | min mr={} cf={} | зависимости {}",
               "version {} | loader {} | prefer {}{} | min mr={} cf={} | dependencies {}").format(
        s['version'] or "?", s['loader'] or "?", s['prefer'], "!" if s['strict'] else "", s['min_mr'], s['min_cf'],
        _t("да", "on") if s['deps'] else _t("нет", "off")) + (_t(" | только релизы", " | only releases") if s.get('releases') else "")


def parse_opts(tokens, s):
    toks = [t for t in tokens if t]
    i=0
    while i < len(toks):
        t, nxt = toks[i].lower(), (toks[i + 1] if i + 1 < len(toks) else "")
        m = re.match(r"^(mr|cf)=(\d+)([km]?)$", t)
        if t == "prefer" and nxt:
            s['strict'] = nxt.endswith("!")
            s['prefer'] = {'m': "M", 'mr': "M", 'modrinth': "M", 'cf': "CF", 'curseforge': "CF"}.get(nxt.lower().rstrip("!"), "auto")
            i += 2
        elif t == "min" and nxt.lower() in ("off", "none", "0"):
            s['min_mr'] = s['min_cf'] = 0
            i += 2
        elif m:
            s["min_" + m.group(1)] = int(m.group(2)) * {"": 1, 'k': 1000, 'm': 1000000}[m.group(3)]
            i += 1
        elif t == "version" and nxt:
            s['version'] = nxt
            i += 2
        elif t == "loader" and nxt:
            s['loader'] = {'neo': "neoforge"}.get(nxt.lower(), nxt.lower())
            i += 2
        elif t == "deps" and nxt:
            s['deps'] = nxt.lower() not in ("off", "no", "n", "0")
            i += 2
        elif t == "only" and nxt.lower().startswith("release"):
            s['releases'] = True
            i += 2
        elif t == "only" and nxt.lower() in ("off", "no", "any", "all"):
            s['releases'] = False
            i += 2
        elif t in ("releases", "release"):
            off = nxt.lower() in ("off", "no", "n", "0")
            s['releases'] = not off
            i += 2 if (off or nxt.lower() in ("on", "yes", "y", "1")) else 1
        elif REL_VER_RE.match(toks[i]):
            s['version'] = toks[i]
            i += 1
        elif t in LOADERS or t == "neo":
            s['loader'] = {'neo': "neoforge"}.get(t, t)
            i += 1
        else:
            i += 1

#F56

def mc_tuple(mc, *names):
    for s in names:
        s = re.sub(r"(?i)\.(jar|zip)$", "", str(s or ""))
        if mc:
            s = s.replace(mc, " ")
        s = re.sub(r"(?i)neoforge|forge|fabric|quilt|minecraft|mc", " ", s)
        best = None
        for t in _NUM_RE.findall(s):
            if best is None or len(t.split(".")) >= len(best.split(".")):
                best = t
        if best:
            return tuple(int(x) for x in best.split("."))
    return ()


def _pad3(vt):
    return (tuple(vt) + (0,) * 8)[:8]       #F57

def _cand_key(c):
    return (_pad3(c['vt']), c['date'])

def _ver_disp(c):
    return ".".join(str(x) for x in c["vt"]) if c["vt"] else str(c["vname"])


def mr_cands(pid, loader, ver, only_rel=False):
    key = f"il_mr_v2:{pid}:{loader}:{ver}:{int(only_rel)}"
    cached = cache_get(key, ttl=FILES_CACHE_TTL)
    if cached != "MISS":
        return cached
    url = "https://api.modrinth.com/v2/project/{}/version?loaders={}&game_versions={}".format(
        pid, urllib.parse.quote(json.dumps([loader])), urllib.parse.quote(json.dumps([ver])))
    data = http_get_json(url)
    if not isinstance(data, list):
        return None
    best = None
    for v in data:
        files = (v.get('files') or []) if isinstance(v, dict) else []
        if not files:
            continue
        if only_rel and v.get('version_type') != "release":
            continue
        f = next((x for x in files if x.get('primary')), files[0])
        hs = f.get('hashes') or {}
        c = {'src': "M", 'pid': pid, 'vt': mc_tuple(ver, v.get('version_number'), f.get('filename')),
             'vname': v.get('version_number') or v.get('name') or "?", 'rank': _REL_RANK.get(v.get('version_type'), 3),
             'vtype': v.get('version_type') or "?", 'date': v.get('date_published') or "", 'filename': f.get('filename'),
             'url': f.get('url'), 'sha1': hs.get('sha1'), 'sha512': hs.get('sha512'), 'size': f.get('size'),
             'host': "modrinth",
             'deps': [[d.get('dependency_type'), d.get('project_id')] for d in (v.get('dependencies') or [])
                      if d.get('project_id')]}
        if best is None or _cand_key(c) > _cand_key(best):
            best = c
    cache_set(key, best)
    return best

def cf_cands(mid, loader, ver, api_key, only_rel=False):
    key = f"il_cf_v2:{mid}:{loader}:{ver}:{int(only_rel)}"
    cached = cache_get(key, ttl=FILES_CACHE_TTL)
    if cached != "MISS":
        return cached
    base = "https://api.curseforge.com/v1/mods/{}/files?gameVersion={}&pageSize=50".format(mid, urllib.parse.quote(ver))
    data = http_get_json(base + f"&modLoaderType={CF_LOADER_IDS[loader]}", headers=cf_headers(api_key))
    if data == None:
        return None
    files = data.get("data") or []
    if not files and loader == "forge" and _vtup(ver) < (1, 14, 0):
        files = (http_get_json(base, headers=cf_headers(api_key)) or {}).get("data") or []
    best = None
    for f in files:
        if not isinstance(f, dict) or not f.get("isAvailable", True):
            continue
        rel = {1: "release", 2: "beta", 3: "alpha"}.get(f.get("releaseType"), "?")
        if only_rel and rel != "release":
            continue
        c = {"src": "CF", "pid": mid, "vt": mc_tuple(ver, f.get("displayName"), f.get("fileName")),
             "vname": f.get("displayName") or f.get("fileName") or "?", "rank": _REL_RANK.get(rel, 3), "vtype": rel,
             "date": f.get("fileDate") or "", "filename": f.get("fileName"), "url": f.get("downloadUrl"),
             "sha1": cf_file_sha1(f), "sha512": None, "size": f.get("fileLength"), "host": "curseforge",
             "deps": [[CF_RELATION_TYPE.get(d.get("relationType"), "embedded"), d.get("modId")]
                      for d in (f.get("dependencies") or []) if d.get("modId")]}
        if best is None or _cand_key(c) > _cand_key(best):
            best = c
    if best is not None and not best["url"] and HASH_MATCH:
        via_modrinth(best)       #F58
    cache_set(key, best)
    return best #FTEMPIMPORTANT3

def choose_cand(cands, s):
    cands = [c for c in cands if c]
    if not cands:
        return None
    pref = {"M": "M", "CF": "CF"}.get(s["prefer"])
    usable = [c for c in cands if c.get("url")] or cands
    if pref and s.get("strict"):
        usable = [c for c in usable if c["src"] == pref] or usable
    top_key = max(_pad3(c["vt"]) for c in usable)
    top = [c for c in usable if _pad3(c["vt"]) == top_key]
    if len(top) > 1:
        low = min(c["rank"] for c in top)
        top = [c for c in top if c["rank"] == low]
    if len(top) > 1:
        for c in top:
            if c["src"] == pref:
                return c
        top.sort(key=lambda c: (c["date"], c["src"] == "M"), reverse=True)
    return top[0]


#F59

def extract_urls(lines):
    out = []
    for ln in lines:
        for u in _URL_RE.findall(ln):
            u = u.rstrip(").,;")
            if u not in out:
                out.append(u)
    return out


def unit_from_url(url, api_key):
    pu = urllib.parse.urlparse(url)
    host = pu.netloc.lower()
    parts = [p for p in pu.path.split("/") if p]
    mr_card = cf_slim = None
    if "modrinth.com" in host:
        if len(parts) < 2 or parts[0] not in ("mod", "project"):
            return None, _t("это не ссылка на мод Modrinth", "not a Modrinth mod link")
        p = mr_by_slug(parts[1])
        if not p or p.get('project_type') not in (None, "mod"):
            return None, _t("не мод или не найден на Modrinth", "not a mod / not found on Modrinth")
        mr_card = card_from_mr_project(p)
    elif "curseforge.com" in host:
        if not api_key:
            return None, _t("для ссылок CurseForge нужен API-ключ (команда key)", "CurseForge links need an API key (key command)")
        if len(parts) >= 3 and parts[:2] == ["minecraft", "mc-mods"]:
            cf_slim = cf_by_slug(parts[2], api_key)
        elif len(parts) >= 2 and parts[0] == "projects" and parts[1].isdigit():
            raw = cf_mod_by_id(parts[1], api_key)
            cf_slim = slim_cf_hit(raw) if raw and raw.get('classId') in (None, CF_CLASS_ID_MODS) else None
        else:
            return None, _t("это не ссылка на мод CurseForge", "not a CurseForge mod link")
        if not cf_slim:
            return None, _t("мод не найден на CurseForge", "mod not found on CurseForge")
    else:
        return None, _t("ссылка не с Modrinth/CurseForge", "not a Modrinth/CurseForge link")
    return {'mr': mr_card, 'cf': cf_slim, 'title': (mr_card or normalize_cf_hit(cf_slim))['title'], 'url': url}, None

def dep_unit(src, did, api_key):
    if src == "M":
        p = mr_by_slug(did)
        if not p or p.get("project_type") not in (None, "mod"):
            return None
        card = card_from_mr_project(p)
        return {"mr": card, "cf": None, "title": card["title"], "url": card["link"]}
    raw = cf_mod_by_id(did, api_key) if api_key else None
    if not raw or raw.get("classId") not in (None, CF_CLASS_ID_MODS):
        return None
    slim = slim_cf_hit(raw)
    return {"mr": None, "cf": slim, "title": slim["name"], "url": normalize_cf_hit(slim)["link"]}


def find_twin(unit, api_key):
    if unit['mr'] and not unit['cf'] and api_key:
        unit['cf'] = other_on_cf(unit['mr'], api_key)
    elif unit['cf'] and not unit['mr']:
        unit['mr'] = mr_for_cf(normalize_cf_hit(unit['cf']), unit['cf'].get('sha1'))


def unit_ids(unit):
    out = set()
    if unit.get("mr"):
        out.add("mr:" + str(unit["mr"]["id"]))
    if unit.get("cf"):
        out.add("cf:" + str(unit["cf"]["id"]))
    return out

def process_unit(unit, s, api_key):
    jobs, notes = [], []
    if unit["mr"]:
        if (unit["mr"].get("downloads") or 0) >= s["min_mr"]:
            jobs.append(lambda: mr_cands(unit["mr"]["id"], s["loader"], s["version"], s.get("releases", False)))
        else:
            notes.append(_t("Modrinth ниже порога (скачиваний: {})", "Modrinth below the threshold ({} downloads)").format(
                unit["mr"].get("downloads") or 0))
    if unit["cf"] and api_key:
        if (unit["cf"].get("downloadCount") or 0) >= s["min_cf"]:
            jobs.append(lambda: cf_cands(unit["cf"]["id"], s["loader"], s["version"], api_key, s.get("releases", False)))
        else:
            notes.append(_t("CurseForge ниже порога (скачиваний: {})", "CurseForge below the threshold ({} downloads)").format(
                unit["cf"].get("downloadCount") or 0))
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as ex:
        cands = list(ex.map(lambda j: j(), jobs))
    return {"cands": cands, "pick": choose_cand(cands, s), "notes": notes}

#F60

def manifest_load(folder):
    try:
        with open(os.path.join(folder, MANIFEST_NAME), "r", encoding="utf-8") as f:
            d = json.load(f)
        return d if isinstance(d, dict) else {}
    except (OSError, ValueError):
        return {}

def manifest_save(folder, man):
    try:
        with open(os.path.join(folder, MANIFEST_NAME), "w", encoding="utf-8") as f:
            json.dump(man, f, ensure_ascii=False, indent=1)
    except OSError:
        pass


def jar_name(c, title):
    fn = re.sub(r'[\\/:*?"<>|]+', "_", os.path.basename(c.get("filename") or "")).strip()
    return fn or (re.sub(r"[^A-Za-z0-9._-]+", "_", title) + ".jar")

def place_file(unit, c, folder, man, lock):
    fn = jar_name(c, unit['title'])
    dest = os.path.join(folder, fn)
    mid, cid = (unit.get('mr') or {}).get('id'), (unit.get('cf') or {}).get('id')
    old = unit.get('replace')
    if not old:
        with lock:
            for ofn, e in man.items():
                if ofn != fn and ((mid and e.get('mr') == mid) or (cid and e.get('cf') == cid)):
                    old = ofn
    state = "present"
    if not (os.path.isfile(dest) and os.path.getsize(dest) > 0):
        if not http_download(c['url'], dest):
            return "failed"
        state = "new"
    if old and old != fn and os.path.isfile(os.path.join(folder, old)):
        os.makedirs(os.path.join(folder, "_old"), exist_ok=True)
        os.replace(os.path.join(folder, old), os.path.join(folder, "_old", old))
        state = "updated"
    with lock:
        if old:
            man.pop(old, None)
        man[fn] = {'title': unit['title'], 'mr': mid, 'cf': cid, 'src': c['src'], 'version': _ver_disp(c),
                   'sha1': c.get('sha1'), 'date': c.get('date')}
    return state


#F61

class ProgressUI:

    def __init__(self, total):
        self.total, self.done, self.ready = total, 0, []
        self.lock = threading.Lock()
        self.live = sys.stdout.isatty()
        self.h = READY_LINES + 3
        self.drawn = False
        if self.live:
            self.draw()

    def bar(self):
        w = BAR_WIDTH
        f = int(w * self.done / self.total) if self.total else w
        pct = int(100 * self.done / self.total) if self.total else 100
        return "[{}{}] {:3d}%  {}/{}".format("#" * f, "-" * (w - f), pct, self.done, self.total)

    def draw(self):
        cols = shutil.get_terminal_size((100, 20)).columns - 1
        lines = [self.bar(), "", "§ Ready"] + self.ready[-READY_LINES:]
        lines += [""] * (self.h - len(lines))
        sys.stdout.write((f"\033[{self.h}A" if self.drawn else "") + "".join("\r\033[K" + l[:cols] + "\n" for l in lines))
        sys.stdout.flush()
        self.drawn = True

    def tick(self, line=None, grow=0):
        with self.lock:
            self.done += 1
            self.total += grow
            if line:
                self.ready.append(line)
            if self.live:
                self.draw()
            else:
                if line:
                    print("§ Ready " + line)
                if self.done % 10 == 0 or self.done == self.total:
                    print(self.bar())

    def grow(self, n):
        with self.lock:
            self.total += n
            if self.live:
                self.draw()


#F62

def run_units(units, s, folder, api_key, known=None):
    man = manifest_load(folder)
    known = set(known or [])
    for e in man.values():
        if e.get('mr'):
            known.add("mr:" + str(e['mr']))
        if e.get('cf'):
            known.add("cf:" + str(e['cf']))
    lock = threading.Lock()
    seen, problems, stats, deps_next = set(), [], {'new': 0, 'updated': 0, 'present': 0}, []
    ui = ProgressUI(len(units))

    def fail(unit, why):
        with lock:
            problems.append((unit.get('title') or unit.get('url') or "?", why, unit.get('url') or ""))
        ui.tick(None)

    def work(unit):
        if "dep" in unit:                                   #F63
            u = dep_unit(unit['dep'][0], unit['dep'][1], api_key)
            if not u:
                return fail({'title': "{}:{}".format(*unit['dep']), 'url': ""}, _t("зависимость не найдена", "dependency not found"))
            unit = u
            if unit_ids(unit) & known:
                return ui.tick(None)
        elif "title" not in unit:                           #F64
            u, why = unit_from_url(unit['url'], api_key)
            if not u:
                return fail(unit, why)
            unit = u
        find_twin(unit, api_key)
        ids = unit_ids(unit)
        with lock:
            if ids & seen:
                dup = True
            else:
                dup = False
                seen.update(ids)
        if dup:
            return ui.tick(None)
        res = process_unit(unit, s, api_key)
        c = res['pick']
        if not c:
            return fail(unit, res['notes'][0] if res['notes'] else _t("нет файла под {} {}", "no file for {} {}").format(
                LOADER_LABEL[s['loader']], s['version']))
        if not c.get('url'):
            return fail(unit, _t("скачать вручную (автор запретил автоскачивание)", "download manually (forbidden by the author)"))
        st = place_file(unit, c, folder, man, lock)
        if st == "failed":
            return fail(unit, _t("не удалось скачать", "download failed"))
        with lock:
            stats[st] += 1
            if s['deps']:
                deps_next.extend({'dep': (c['src'], d[1]), 'who': unit['title']} for d in c['deps'] if d[0] == "required")
        mark = {'new': "", 'updated': _t('(обновлён)', '(updated)'), 'present': _t('(уже есть)', '(already there)')}[st]
        ui.tick("-{} -{}- [{}] ({}){}{}".format(unit['title'], _ver_disp(c), jar_name(c, unit['title']), c['src'], mark,
                                         "" if c['vtype'] in ("release", "?") else " [" + c['vtype'] + "]"))

    def safe(unit):
        try:
            work(unit)
        except Exception as e:
            fail(unit if "title" in unit else {'title': unit.get('url') or str(unit.get('dep')), 'url': ""},
                 _t("ошибка: {}", "error: {}").format(e))

    queue, depth = list(units), 0
    try:
        while queue and depth < 5:
            depth += 1
            deps_next[:] = []
            _parallel_map(safe, queue, workers=IMPORT_WORKERS)
            queue = list(deps_next)
            if queue and s['deps']:
                ui.grow(len(queue))
            else:
                queue = []
    finally:
        manifest_save(folder, man)
        save_cache()
    say()
    say(f"{GREEN}{BOLD}" + _t("Готово: новых {}, обновлено {}, уже было {}, проблем {}.", "Done: new {}, updated {}, already there {}, problems {}.").format(
        stats['new'], stats['updated'], stats['present'], len(problems)) + RESET)
    for title, why, url in problems:
        say(YELLOW + f"  {title} - {why} {url}" + RESET)
    try:
        with open(os.path.join(folder, "importlink_log.txt"), "a", encoding="utf-8") as f:
            f.write(f"== {time.strftime('%Y-%m-%d %H:%M')} | {s['loader']} {s['version']} | {show_settings(s)}\n")
            for line in ui.ready:
                f.write(line + "\n")
            for title, why, url in problems:
                f.write(f"! {title} - {why} {url}\n")
    except OSError:
        pass
    say(_t("Папка: {}", "Folder: {}").format(folder))
    return stats, problems

#F65

def pending_input(wait=0.3):
    #F72
    out = []
    try:
        import select
        while sys.stdin.isatty() and select.select([sys.stdin], [], [], wait)[0]:
            ln = sys.stdin.readline()
            if not ln:
                break
            out.append(ln.rstrip("\r\n"))
            wait = 0.15
    except (ImportError, OSError, ValueError):
        pass
    return out


def block_input(prompt):
    first = _ask(prompt)
    if first is None:
        return None
    return [first] + pending_input(0.3)

def is_yes(ans, default=True):
    a = (ans or "").strip().lower()
    return default if not a else a in ("y", "yes", "д", "да", "1")

def ask_target(s, stash=None):
    stash = [] if stash is None else stash
    while True:
        v = _ask(_t("Версия Minecraft [{}]: ", "Minecraft version [{}]: ").format(s['version'] or "1.20.1"))
        if v is None:
            return False
        if _URL_RE.search(v):
            stash.append(v)
            continue
        v = v or s['version']
        if REL_VER_RE.match(v or ""):
            s['version'] = v
            break
        say(_t("Нужна версия вида 1.20.1", "Need a version like 1.20.1"))
    while True:
        lo = _ask(_t("Загрузчик (forge/fabric/neoforge/quilt) [{}]: ", "Loader (forge/fabric/neoforge/quilt) [{}]: ").format(
            s['loader'] or "forge"))
        if lo is None:
            return False
        if _URL_RE.search(lo):
            stash.append(lo)
            continue
        lo = {'neo': "neoforge"}.get((lo or s['loader']).lower(), (lo or s['loader']).lower())
        if lo in LOADERS:
            s['loader'] = lo
            break
        say(_t("Загрузчик: forge, fabric, neoforge или quilt", "Loader: forge, fabric, neoforge or quilt"))
    save_settings(s)
    return True



def pick_folder(s, create=True):
    base = SCRIPT_DIR
    while True:
        say(_t("Папка для модов:", "Folder for the mods:"))
        if create:
            say(_t('1) создать новую папку рядом со скриптом', '1) create a new folder next to the script'))
        say(_t('2) использовать готовую папку (рядом со скриптом)', '2) use an existing folder (next to the script)'))
        say(_t('3) использовать папку скрипта, ничего не создавая', '3) use the script folder without creating anything'))
        ch = _ask(_t('Выбор [{}]:', 'Choice [{}]:').format("1" if create else "2"))
        if ch is None:
            return None
        ch = ch or ("1" if create else "2")
        if ch == "3":
            return base
        if ch == "2":
            subs = sorted(d for d in os.listdir(base) if os.path.isdir(os.path.join(base, d))
                          and not d.startswith((".", "_")) and d not in ("found_mods", "__pycache__"))
            if not subs:
                say(_t("Готовых папок рядом со скриптом нет.", "No folders next to the script."))
                continue
            for i, d in enumerate(subs, 1):
                say(f"  {i}) {d}")
            n = _ask(_t('Номер или название папки:', 'Folder number or name:'))
            if n is None:
                return None
            if n.isdigit() and 1 <= int(n) <= len(subs):
                return os.path.join(base, subs[int(n) - 1])
            if n and os.path.isdir(os.path.join(base, n)):
                return os.path.join(base, n)
            say(_t("Такой папки нет.", "No such folder."))
            continue
        if ch == "1" and create:
            default = f"mods_{s['loader']}_{s['version']}"
            name = _ask(_t('Название новой папки [{}]:', 'New folder name [{}]:').format(default))
            if name is None:
                return None
            name = re.sub(r'[\\/:*?"<>|]+', "_", name or default).strip() or default
            path = os.path.join(base, name)
            os.makedirs(path, exist_ok=True)
            return path

def run_batch(urls, s, st, api_key):
    n_mr = sum(1 for u in urls if "modrinth.com" in u.lower())
    n_cf = sum(1 for u in urls if "curseforge.com" in u.lower())
    say(_t("Ссылок: {} (Modrinth {}, CurseForge {}); {} {}; prefer {}{}", "Links: {} (Modrinth {}, CurseForge {}); {} {}; prefer {}{}").format(
        len(urls), n_mr, n_cf, LOADER_LABEL[s["loader"]], s["version"], s["prefer"], "!" if s["strict"] else ""))
    ans = _ask(_t('Установить? y/n [y]:', 'Install? y/n [y]:'))
    if ans is None or not is_yes(ans):
        say(T[LANG]["cancelled"])
        return
    if not st.get("folder"):
        st["folder"] = pick_folder(s)
        if not st["folder"]:
            return
    try:
        run_units([{"url": u} for u in urls], s, st["folder"], api_key)
    except KeyboardInterrupt:
        _CANCEL.clear()
        say()
        say(f"{YELLOW}{T[LANG]['interrupted']}{RESET}")


def link_session(s, api_key, lines, stay):
    ok_n = 0
    say(f"{GREEN}{BOLD}{_t('=== importlink: скачивание по ссылкам Modrinth/CurseForge ===', '=== importlink: download by Modrinth/CurseForge links ===')}{RESET}")
    say(_t("Вставьте ссылки (по одной или списком). Команды: prefer CF|M|auto[!], min mr=N cf=N | min off, only releases | only off, version X, loader Y, deps on|off, folder, settings, exit.",
            "Paste links (one by one or a list). Commands: prefer CF|M|auto[!], min mr=N cf=N | min off, only releases | only off, version X, loader Y, deps on|off, folder, settings, exit."))
    pend = list(lines) + pending_input(0.35)
    stash = []
    if not ask_target(s, stash):
        return
    pend += stash
    st = {"folder": None}
    while True:
        for ln in pend:
            if ln.strip() and not _URL_RE.search(ln):
                w = ln.split()
                if w[0].lower() in ("exit", "back", "q", "quit"):
                    save_settings(s)
                    return
                if w[0].lower() == "folder":
                    st["folder"] = None
                elif w[0].lower() == "settings":
                    say(show_settings(s))
                else:
                    parse_opts(w, s)
                    say(show_settings(s))
        save_settings(s)
        urls = extract_urls(pend)
        if urls:
            run_batch(urls, s, st, api_key)
            if not stay:
                return
        pend = block_input("importlink> ")
        if pend is None or not any(p.strip() for p in pend):
            return


def do_importlink(args, api_key):
    s = load_settings()
    parse_opts(args, s)
    link_session(s, api_key, [], True)

def do_import_urls(line, api_key):
    link_session(load_settings(), api_key, [line], False)


#F66

def murmur2(data):
    #F73
    m = 0x5bd1e995
    data = bytes(b for b in data if b not in (9, 10, 13, 32))
    n = len(data)
    h = (1 ^ n) & 0xFFFFFFFF
    i = 0
    while n >= 4:
        k = data[i] | (data[i + 1] << 8) | (data[i + 2] << 16) | (data[i + 3] << 24)
        k = (k * m) & 0xFFFFFFFF
        k ^= k >> 24
        k = (k * m) & 0xFFFFFFFF
        h = ((h * m) & 0xFFFFFFFF) ^ k
        i += 4
        n -= 4
    if n == 3:
        h ^= data[i + 2] << 16
    if n >= 2:
        h ^= data[i + 1] << 8
    if n >= 1:
        h ^= data[i]
        h = (h * m) & 0xFFFFFFFF
    h ^= h >> 13
    h = (h * m) & 0xFFFFFFFF
    h ^= h >> 15
    return h

def identify_mods(paths, folder, api_key):
    man, sha, fp, info = manifest_load(folder), {}, {}, {}
    for p in paths:
        with open(p, "rb") as f:
            data = f.read()
        sha[p], fp[p] = hashlib.sha1(data).hexdigest(), murmur2(data)
        e = man.get(os.path.basename(p))
        if e and e.get("sha1") == sha[p]:
            info[p] = {"mr": e.get("mr"), "cf": e.get("cf"), "vname": e.get("version"), "date": e.get("date") or "", "sha1": sha[p]}
    rest = [p for p in paths if p not in info]
    for i in range(0, len(rest), 100):
        chunk = rest[i:i + 100]
        data = http_post_json("https://api.modrinth.com/v2/version_files", {"hashes": [sha[p] for p in chunk], "algorithm": "sha1"})
        for p in chunk:
            v = data.get(sha[p]) if isinstance(data, dict) else None
            if isinstance(v, dict) and v.get("project_id"):
                info[p] = {"mr": v["project_id"], "cf": None, "vname": v.get("version_number"), "date": v.get("date_published") or "",
                           "sha1": sha[p]}
    rest = [p for p in paths if p not in info]
    if api_key and rest:
        for i in range(0, len(rest), 200):
            chunk = rest[i:i + 200]
            data = http_post_json("https://api.curseforge.com/v1/fingerprints/432", {"fingerprints": [fp[p] for p in chunk]},
                                    cf_headers(api_key))
            by_fp = {}
            for m in ((data or {}).get("data") or {}).get("exactMatches") or []:
                f = m.get("file") or {}
                by_fp[f.get("fileFingerprint")] = (m.get("id"), f)
            for p in chunk:
                if fp[p] in by_fp:
                    mid, f = by_fp[fp[p]]
                    info[p] = {"mr": None, "cf": mid, "vname": f.get("displayName") or f.get("fileName"),
                               "date": f.get("fileDate") or "", "sha1": sha[p]}
    return info


def check_updates(paths, info, s, api_key):
    ui = ProgressUI(len(paths))
    out, lock = [], threading.Lock()

    def one(p):
        try:
            i = info.get(p)
            if not i:
                return ui.tick(None)
            unit = {"mr": None, "cf": None, "title": None, "url": "", "replace": os.path.basename(p)}
            if i.get("mr"):
                pr = mr_by_slug(i["mr"])
                unit["mr"] = card_from_mr_project(pr) if pr else None
            if i.get("cf") and api_key:
                raw = cf_mod_by_id(i["cf"], api_key)
                unit["cf"] = slim_cf_hit(raw) if raw else None
            if not (unit["mr"] or unit["cf"]):
                return ui.tick(None)
            unit["title"] = (unit["mr"] or normalize_cf_hit(unit["cf"]))["title"]
            find_twin(unit, api_key)
            c = process_unit(unit, s, api_key)["pick"]
            if c and c.get("url") and c.get("sha1") != i["sha1"]:
                ivt = mc_tuple(s["version"], i.get("vname"), os.path.basename(p))
                if (ivt and c["vt"] and _pad3(c["vt"]) > _pad3(ivt)) or (not (ivt and c["vt"]) and c["date"] > i["date"] > ""):
                    with lock:
                        out.append({"path": p, "unit": unit, "old": ".".join(map(str, ivt)) or str(i.get("vname") or "?"),
                                    "new": _ver_disp(c) + ("" if c["vtype"] in ("release", "?") else " [" + c["vtype"] + "]"), "src": c["src"]})
            ui.tick("-{}".format(unit["title"]))
        except Exception:
            ui.tick(None)

    _parallel_map(one, paths, workers=IMPORT_WORKERS)
    return sorted(out, key=lambda u: u["unit"]["title"].lower())


def do_update(args, api_key):
    s = load_settings()
    parse_opts(args, s)
    say(f"{GREEN}{BOLD}{_t('=== update: обновление модов в папке ===', '=== update: updating mods in a folder ===')}" + RESET)
    folder = pick_folder(s, create=False)
    if not folder or not ask_target(s):
        return
    paths = sorted(os.path.join(folder, f) for f in os.listdir(folder) if f.lower().endswith(".jar"))
    if not paths:
        say(_t("В папке нет .jar файлов.", "No .jar files in the folder."))
        return
    if not check_internet():
        say(f"{RED}{T[LANG]['no_internet']}{RESET}")
        return
    _CANCEL.clear()
    try:
        say(_t("Определяю моды ({})...", "Identifying mods ({})...").format(len(paths)))
        info = identify_mods(paths, folder, api_key)
        say(_t("Определено {} из {}. Ищу новые версии для {} {}...", "Identified {} of {}. Looking for newer versions for {} {}...").format(
            len(info), len(paths), LOADER_LABEL[s["loader"]], s["version"]))
        plan = check_updates(paths, info, s, api_key)
        say()
        unknown = [os.path.basename(p) for p in paths if p not in info]
        if unknown:
            say(YELLOW + _t("Не определено (не трогаю): {}", "Not identified (left alone): {}").format(", ".join(unknown)) + RESET)
        if not plan:
            say(f"{GREEN}{_t('Все определённые моды уже новейшие.', 'All identified mods are already the newest.')}{RESET}")
            return
        say(BOLD + _t("Доступны обновления ({}):", "Updates available ({}):").format(len(plan)) + RESET)
        for u in plan:
            say("  {}: {} -> {} ({})".format(u["unit"]["title"], u["old"], u["new"], u["src"]))
        ans = _ask(_t('Установить: a = все сразу, o = по одному, n = отмена [a]:', 'Install: a = all at once, o = one by one, n = cancel [a]:'))
        if ans is None or ans.lower() in ("n", "no", "н", "нет"):
            say(T[LANG]["cancelled"])
            return
        chosen = plan
        if ans.lower() in ("o", "о", "one"):
            chosen = []
            for k, u in enumerate(plan):
                a = _ask(_t('{}: {} -> {} ({}). y = да, n = пропустить, a = все оставшиеся, q = стоп [y]:', '{}: {} -> {} ({}). y = yes, n = skip, a = all remaining, q = stop [y]:').format(
                                       u["unit"]["title"], u["old"], u["new"], u["src"]))
                if a is None or a.lower() == "q":
                    break
                if a.lower() == "a":
                    chosen.extend(plan[k:])
                    break
                if is_yes(a):
                    chosen.append(u)
        if not chosen:
            say(_t("Нечего устанавливать.", "Nothing to install."))
            return
        known = set()
        for i in info.values():
            if i.get("mr"):
                known.add("mr:" + str(i["mr"]))
            if i.get("cf"):
                known.add("cf:" + str(i["cf"]))
        run_units([u["unit"] for u in chosen], s, folder, api_key, known)
    except KeyboardInterrupt:
        _CANCEL.clear()
        say()
        say(YELLOW + T[LANG]["interrupted"] + RESET)


NEW_MAX_PAGES = 4            #F67 #F74
CHAIN_DEPTH = 3          #F75
NEW_CACHE_TTL = 3600         #F76
PERIOD_UNITS = (("d", ("d", "day", "days", "д", "дн", "дня", "день", "дней")),
            ("w", ("w", "week", "weeks", "нед", "неделя", "недели", "неделю", "недель")),
            ("m", ("m", "mo", "mon", "month", "months", "мес", "месяц", "месяца", "месяцев")),
            ("y", ("y", "yr", "year", "years", "г", "год", "года", "лет")))


def today_dt():
    return datetime.date.today()

def date_back(today, n, unit):
    if unit == "d":
        return today - datetime.timedelta(days=n)
    if unit == "w":
        return today - datetime.timedelta(weeks=n)
    months = n if unit == "m" else 12 * n
    y, m = today.year, today.month - months
    while m <= 0:
        m += 12
        y -= 1
    return datetime.date(y, m, min(today.day, calendar.monthrange(y, m)[1]))


def parse_period(text):
    n, unit = 1, "w"
    for num, word in re.findall(r"(\d+)?\s*([a-zа-яё]+)", (text or "").lower()):
        hit = next((u for u, names in PERIOD_UNITS if word in names), None)
        if hit:
            n, unit = (int(num) if num else 1), hit
            break
    label = {'d': _t("{} дн.", "{}d"), 'w': _t("{} нед.", "{}w"), 'm': _t("{} мес.", "{}mo"), 'y': _t("{} г.", "{}y")}[unit]
    return date_back(today_dt(), n, unit), label.format(n)

def mr_new_projects(qn, since):
    key = f"nl_mr_v1:{qn.lower()}:{since}"
    cached = cache_get(key, ttl=NEW_CACHE_TTL)
    if cached != "MISS":
        return cached
    out, ok = [], True
    for p in range(NEW_MAX_PAGES):
        url = "https://api.modrinth.com/v2/search?query={}&index=newest&facets={}&limit={}&offset={}".format(
            urllib.parse.quote(qn), urllib.parse.quote(json.dumps([["project_type:mod"]])), PAGE_SIZE, p * PAGE_SIZE)
        data = http_get_json(url)
        if data is None:
            ok = False
            break
        hits = data.get('hits', [])
        for h in mr_only_mods(hits):
            d = (h.get('date_created') or "")[:10]
            if d >= since:
                slim = dict((k, h.get(k)) for k in ("project_id", "slug", "title", "description", "downloads", "categories"))
                slim['date'] = d
                out.append(slim)
        if len(hits) < PAGE_SIZE or (hits[-1].get('date_created') or "")[:10] < since:
            break
    if ok:
        cache_set(key, out)
    return out


def cf_new_projects(qn, api_key, since):
    key = f"nl_cf_v1:{qn.lower()}:{since}"
    cached = cache_get(key, ttl=NEW_CACHE_TTL)
    if cached != "MISS":
        return cached
    out, ok = [], True
    for p in range(NEW_MAX_PAGES):
        url = ("https://api.curseforge.com/v1/mods/search?gameId=432&classId={}&searchFilter={}&pageSize={}&index={}"
               "&sortField=11&sortOrder=desc").format(CF_CLASS_ID_MODS, urllib.parse.quote(qn), PAGE_SIZE, p * PAGE_SIZE)
        data = http_get_json(url, headers=cf_headers(api_key))
        if data is None:
            ok = False
            break
        items = cf_only_mods(data.get("data", []))
        dates = []
        for h in items:
            d = (h.get("dateReleased") or h.get("dateCreated") or "")[:10]
            dates.append(d)
            if d >= since:
                slim = slim_cf_hit(h)
                slim["date"] = d
                out.append(slim)
        if len(data.get("data", [])) < PAGE_SIZE or (dates and max(dates) < since):
            break
    if ok:
        cache_set(key, out)
    return out

def edges_of(side, pid, api_key):
    if side == "mr":
        return [(d[0], d[1]) for d in (modrinth_latest_version_deps(pid) or []) if len(d) >= 2 and d[1]]
    return [(d[0], d[1]) for d in (cf_latest_file_deps(pid, api_key) or []) if len(d) >= 2 and d[1]]


def title_of(side, pid, api_key):
    if side == "mr":
        return (mr_by_slug(pid) or {}).get('title') or str(pid)
    return (cf_mod_by_id(pid, api_key) or {}).get('name') or str(pid)


def dep_chain(side, edges, main_id, api_key, depth, seen):
    for kind, did in edges:
        if did == main_id and kind in ("required", "optional"):
            return []
    if depth > 1:
        for kind, did in edges:
            if kind != "required" or (side, did) in seen:
                continue
            seen.add((side, did))
            sub = dep_chain(side, edges_of(side, did, api_key), main_id, api_key, depth - 1, seen)
            if sub is not None:
                return [title_of(side, did, api_key)] + sub
    return None

def vers_of(pres):
    parts = []
    for lo in LOADERS:
        vs = sorted(pres.get(lo, ()), key=_vtup, reverse=True)
        if vs:
            parts.append(f"{LOADER_LABEL[lo]}: {', '.join(vs[:4])}{' ...' if len(vs) > 4 else ''}")
    return " | ".join(parts) or "-"


def collect_new(main_words, nt, since, mid, cid, api_key, qn):
    hits_mr = mr_new_projects(qn, since) if mid else []
    hits_cf = cf_new_projects(qn, api_key, since) if (cid and api_key) else []
    recs, lock = [], threading.Lock()

    def one(item):
        side, h = item
        if side == "mr":
            if h["project_id"] == mid:
                return
            rec = mr_record(normalize_modrinth_hit(h))
            main_id = mid
        else:
            if h["id"] == cid:
                return
            rec = cf_record(h, api_key)
            main_id = cid
        rec["date"] = h["date"]
        rec["chain"] = dep_chain(side, rec["edges"], main_id, api_key, CHAIN_DEPTH, set())
        text = _blob(rec["card"].get("title"), rec["card"].get("slug"))
        rec["lookalike"] = nt in text or all(w in text for w in main_words)
        with lock:
            recs.append(rec)

    _parallel_map(one, [("mr", h) for h in hits_mr] + [("cf", h) for h in hits_cf])
    return recs, len(hits_mr) + len(hits_cf)

def merge_new(recs):
    out = []
    for r in sorted(recs, key=lambda x: (x['side'], x['card'].get('title') or "")):
        slug = (r['card'].get('slug') or "").lower()
        for e in out:
            same = bool(slug) and any((x['card'].get('slug') or "").lower() == slug for x in e['sides'].values())
            if r['side'] not in e['sides'] and (same or norm_title(e['title']) == norm_title(r['card'].get('title'))):
                e['sides'][r['side']] = r
                break
        else:
            out.append({'title': r['card'].get('title') or "?", 'sides': {r['side']: r}})
    for e in out:
        rs = list(e['sides'].values())
        e['date'] = min(r['date'] for r in rs)
        e['pres'] = {}
        for r in rs:
            for lo, vs in r['pres'].items():
                e['pres'].setdefault(lo, set()).update(vs)
        chains = [r['chain'] for r in rs if r['chain'] is not None]
        e['chain'] = min(chains, key=len) if chains else None
        e['links'] = [r['card'].get('link') for r in rs if r['card'].get('link')]
        e['tag'] = "[M x CF]" if len(rs) == 2 else ("[M]" if "mr" in e['sides'] else "[CF]")
    return out


def created_since(e, since, api_key):
    if len(e["sides"]) == 2:
        return True
    try:
        if "mr" in e["sides"] and api_key:
            slim = other_on_cf(e["sides"]["mr"]["card"], api_key)
            raw = cf_mod_by_id(slim["id"], api_key) if slim else None
            d = ((raw or {}).get("dateReleased") or (raw or {}).get("dateCreated") or "")[:10]
        elif "cf" in e["sides"]:
            rec = e["sides"]["cf"]
            card = mr_for_cf(rec["card"], rec.get("hashes"))
            p = http_get_json("https://api.modrinth.com/v2/project/" + urllib.parse.quote(str(card["id"]), safe="")) if card else None
            d = ((p or {}).get("published") or "")[:10]
        else:
            return True
    except Exception:
        return True
    return not d or d >= since


def do_newaddons(args, api_key):
    n_old = 0
    tr = T[LANG]
    if not args:
        say(_t("Использование: newaddons <ссылка|slug> [период: 7d, 2w, 3m, неделя, 2 мес...] [загрузчик] [версия]",
                "Usage: newaddons <link|slug> [period: 7d, 2w, 3m, week, 2 months...] [loader] [version]"))
        return
    if not check_internet():
        say(f"{RED}{tr['no_internet']}{RESET}")
        return
    _CANCEL.clear()
    loaders, versions, rest = [], [], []
    for a in args[1:]:
        low = {"neo": "neoforge"}.get(a.lower(), a.lower())
        if low in LOADERS:
            loaders.append(low)
        elif REL_VER_RE.match(a):
            versions.append(a)
        else:
            rest.append(a)
    since_d, label = parse_period(" ".join(rest))
    since = since_d.isoformat()
    if not api_key:
        say(f"{YELLOW}{tr['search_cf_skipped']}{RESET}")
    mr_card, cf_slim = find_main_mod(args[0], api_key)
    if not mr_card and not cf_slim:
        say(f"{RED}{T[LANG]['mod_not_found']}{RESET}")
        return
    title = (mr_card or normalize_cf_hit(cf_slim))["title"]
    qn = _qname(title)
    words = [w for w in (_blob(x) for x in re.split(r"[\W_]+", qn)) if len(w) >= 3]
    say(f"{GREEN}{BOLD}" + _t("=== Новые аддоны к '{}' за {} (с {}) ===", "=== New addons of '{}' for {} (since {}) ===").format(
        title, label, since) + RESET)
    if cf_slim is None and api_key:
        say(f"{YELLOW}{_t('Этого мода нет на CurseForge (или не найден), смотрю только Modrinth.', 'Mod is not on CurseForge (or not found), looking at Modrinth only.')}" + RESET)
    try:
        recs, n = collect_new(words, _blob(qn), since, mr_card["id"] if mr_card else None,
                              cf_slim["id"] if cf_slim else None, api_key, qn)
    except KeyboardInterrupt:
        _CANCEL.clear()
        say(f"{YELLOW}{T[LANG]['interrupted']}{RESET}")
        return
    save_cache()
    items = [e for e in merge_new(recs) if created_since(e, since, api_key)]
    if loaders or versions:
        items = [e for e in items if any((not loaders or lo in loaders) and (not versions or v in versions)
                                         for lo, vs in e["pres"].items() for v in vs)]
    real = sorted([e for e in items if e["chain"] is not None], key=lambda e: (e["date"], e["title"].lower()), reverse=True)
    maybe = sorted([e for e in items if e["chain"] is None and any(r["lookalike"] for r in e["sides"].values())],
                   key=lambda e: (e["date"], e["title"].lower()), reverse=True)[:20]

    def show(e):
        if e["chain"] is None:
            how = _t("зависимость не указана", "no dependency declared")
        elif not e["chain"]:
            how = _t("напрямую", "directly")
        else:
            how = _t("через ", "via ") + " > ".join(e["chain"])
        say(f"{e['date']}  {e['title']} {e['tag']}  ({how})")
        say(f"    {vers_of(e['pres'])}")
        say(f"    {' | '.join(e['links'])}")

    if real:
        for e in real:
            show(e)
    else:
        say(_t("Новых аддонов за этот период не найдено.", "No new addons found for this period."))
    if maybe:
        say()
        say(BOLD + _t("Возможные (название похоже, зависимость не указана):",
                       "Possible (similar name, no dependency declared):") + RESET)
        for e in maybe:
            show(e)
    say(tr["commands"])


def main():
    choose_language()
    print_banner()
    api_key = load_cf_key()
    while True:
        try:
            line = input("> ").strip()
        except EOFError:
            break
        except KeyboardInterrupt:
            say()
            break
        if not line:
            continue
        parts = line.split()
        if parts[0] in ("search", "bulk") and ('"' in line or "'" in line):
            try:
                parts = shlex.split(line)   #F29
            except ValueError:
                pass
        cmd = parts[0]
        args = parts[1:]

        try:
            if cmd == "key" and args:
                api_key=" ".join(args).strip()
                save_cf_key(api_key)
                say(f"{GREEN}{T[LANG]['key_set']}{RESET}")
            elif cmd == "search":
                do_search(args, api_key)
            elif cmd == "show":
                do_show(args, api_key)
            elif cmd == "save":
                do_save(args, api_key)
            elif cmd == "saveall":
                do_saveall(api_key)
            elif cmd == "bulk":
                do_bulk(args, api_key)
            elif cmd == "addons":
                do_addons(args, api_key)
            elif cmd == "build":
                do_build(args, api_key)
            elif cmd == "newaddons":
                do_newaddons(args, api_key)
            elif cmd == "importlink":
                do_importlink(args, api_key)
            elif cmd == "update":
                do_update(args, api_key)
            elif is_url(cmd):
                do_import_urls(line, api_key)
            elif cmd == "help":
                do_help()
            elif cmd == "exit":
                break
            else:
                say(T[LANG]["commands"])
        except KeyboardInterrupt:
            say()
            say(f"{YELLOW}{T[LANG]['bulk_interrupted']}{RESET}")
        except Exception as e:
            #F30
            say(f"{RED}{_t('Неожиданная ошибка', 'Unexpected error')}: {e}{RESET}") #F77

    save_cache() 


if __name__ == "__main__":
    main()
'''

def _init_auto_finder():
    namespace = {
        "__name__": "_embedded_auto_finder",
        "__file__": __file__,
        "__package__": None,
    }
    exec(compile(_AUTO_FINDER_SOURCE, __file__ + " [Auto-Finder]", "exec"), namespace, namespace)
    namespace["say"] = say
    namespace["LANG"] = LANG
    for locale in ("ru", "en"):
        commands = namespace["T"][locale].get("commands", "")
        namespace["T"][locale]["commands"] = commands.replace(" | update | ", " | modupdate | ")
    namespace["T"]["ru"]["help_build"] += " Если целевая версия и загрузчик уже заданы в Auto-Modpacker, build использует их по умолчанию; явные аргументы build имеют приоритет."
    namespace["T"]["en"]["help_build"] += " When the Auto-Modpacker target Minecraft version and loader are set, build uses them by default; explicit build arguments take priority."
    namespace["T"]["ru"]["help_update"] = namespace["T"]["ru"]["help_update"].replace(
        "update [версия]", "modupdate [версия]", 1
    )
    namespace["T"]["en"]["help_update"] = namespace["T"]["en"]["help_update"].replace(
        "update [version]", "modupdate [version]", 1
    )
    return namespace


_AUTO_FINDER = _init_auto_finder()

# разовый перенос старого кэша фаиндера: .mod_finder_cache.json -> finder:* в общем кэше
_finder_old_cache = {}
try:
    with open(os.path.join(SCRIPT_DIR, ".mod_finder_cache.json"), "r", encoding="utf-8") as _f:
        _finder_loaded = json.load(_f)
    if isinstance(_finder_loaded, dict):
        _finder_old_cache = _finder_loaded
except (OSError, ValueError):
    pass
if _finder_old_cache:
    for _key, _entry in _finder_old_cache.items():
        if isinstance(_entry, dict) and "ts" in _entry:
            if str(_key).startswith("mr_bslug_v1k:") and not all(
                field in (_entry.get("v") or {}) for field in ("client_side", "server_side")
            ):
                continue
            _shared_key = "finder:" + str(_key)
            _current_entry = CACHE.get(_shared_key)
            if not isinstance(_current_entry, dict) or _entry.get("ts", 0) > _current_entry.get("ts", 0):
                CACHE[_shared_key] = {"v": _entry.get("v"), "ts": _entry.get("ts", time.time()), "fmt": 2}
    save_cache()  # сразу сохраняем объединённый кэш в общий файл
    try:
        os.remove(os.path.join(SCRIPT_DIR, ".mod_finder_cache.json"))  # перенесён в общий кэш
    except OSError:
        pass


def _finder_cache_get(key, ttl=None):
    entry = CACHE.get("finder:" + str(key))
    if not isinstance(entry, dict) or "ts" not in entry:
        return "MISS"
    lifetime = ttl if ttl is not None else _AUTO_FINDER["CACHE_TTL_SECONDS"]
    if time.time() - entry["ts"] > lifetime:
        return "MISS"
    return entry.get("v")


def _finder_cache_set(key, value):
    CACHE["finder:" + str(key)] = {"v": value, "ts": time.time(), "fmt": 2}


def _finder_auth_error(host):
    if "curseforge" in str(host).lower():
        NET_STATS["cf_denied"] = True
    seen = _AUTO_FINDER.get("_AUTH_WARNED")
    if isinstance(seen, set) and host in seen:
        return
    if isinstance(seen, set):
        seen.add(host)
    _AUTO_FINDER["say"](f"{YELLOW}[{host}] {_AUTO_FINDER['T'][LANG]['auth_error']}{RESET}")


_AUTO_FINDER["CACHE"] = CACHE
_AUTO_FINDER["CACHE_PATH"] = CACHE_PATH
_AUTO_FINDER["cache_get"] = _finder_cache_get
_AUTO_FINDER["cache_set"] = _finder_cache_set
_AUTO_FINDER["save_cache"] = save_cache
_AUTO_FINDER["_note_auth_error"] = _finder_auth_error


_FINDER_FIND_MAIN_MOD_BASE = _AUTO_FINDER["find_main_mod"]


def _finder_find_main_mod(target, api_key):
    raw = str(target or "").strip()
    candidates = [raw.lower()]
    if _AUTO_FINDER["is_url"](raw):
        parsed = urllib.parse.urlparse(raw)
        parts = [part for part in parsed.path.split("/") if part]
        if parts:
            candidates.append(parts[-1].lower())
    if LAST_RUN:
        for mod in LAST_RUN.get("mods", []):
            values = [mod.get("modid"), mod.get("display"), mod.get("fname"),
                      mod.get("modrinth_id"), mod.get("cf_slug"), mod.get("cf_id")]
            normalized = {str(value).strip().lower() for value in values if value is not None and str(value).strip()}
            if not normalized.intersection(candidates):
                continue
            if mod.get("modrinth_id"):
                local_target = "https://modrinth.com/mod/" + str(mod["modrinth_id"])
            elif mod.get("cf_slug"):
                local_target = "https://www.curseforge.com/minecraft/mc-mods/" + str(mod["cf_slug"])
            elif mod.get("cf_id"):
                local_target = "https://www.curseforge.com/minecraft/mc-mods/" + str(mod["cf_id"])
            else:
                local_target = mod.get("modid") or raw
            return _FINDER_FIND_MAIN_MOD_BASE(local_target, api_key)
    return _FINDER_FIND_MAIN_MOD_BASE(target, api_key)


_AUTO_FINDER["find_main_mod"] = _finder_find_main_mod


_CLASSIFY_MOD_BASE = classify_mod


def _finder_apply_project_match(m, mr_card, cf_slim, api_key, note=""):
    finder = _AUTO_FINDER
    if mr_card:
        mr_id = mr_card.get("id") or mr_card.get("slug")
        if mr_id:
            m["modrinth_id"] = mr_id
        m["downloads"] = mr_card.get("downloads", m.get("downloads", 0)) or m.get("downloads", 0)
        try:
            mr_data = finder["mr_by_slug"](mr_id) or {}
            if m.get("side_class") in (None, "unknown"):
                client_val = mr_data.get("client_side")
                server_val = mr_data.get("server_side")
                resolved_side = side_from_vals(client_val, server_val)
                if resolved_side:
                    m["client_side"] = client_val if client_val in SIDE_VALID else None
                    m["server_side"] = server_val if server_val in SIDE_VALID else None
                    m["side_class"] = resolved_side
                    m["side_note"] = "Modrinth" + (" / " + note if note else "")
        except Exception:
            pass
    if cf_slim:
        m["cf_id"] = cf_slim.get("id") or m.get("cf_id")
        m["cf_slug"] = cf_slim.get("slug") or m.get("cf_slug")
    if m.get("side_class") in (None, "unknown") and m.get("cf_id") and api_key:
        try:
            cf_client, cf_server = curseforge_side_from_files(fetch_curseforge_files(m["cf_id"], api_key))
            resolved_side = side_from_vals(cf_client, cf_server)
            if resolved_side:
                m["client_side"] = cf_client
                m["server_side"] = cf_server
                m["side_class"] = resolved_side
                m["side_note"] = T[LANG]["cf_fallback_tag"].strip()
        except Exception:
            pass
    m["finder_mr_card"] = mr_card or m.get("finder_mr_card")
    m["finder_cf_slim"] = cf_slim or m.get("finder_cf_slim")


def _finder_lookup_metadata_url(url, api_key):
    try:
        return _FINDER_FIND_MAIN_MOD_BASE(url, api_key)
    except Exception:
        return None, None


def _finder_lookup_metadata_name(name, api_key):
    finder = _AUTO_FINDER
    mr_card = cf_slim = None
    query = str(name or "").strip()
    if not query or len(query) < 3:
        return None, None
    try:
        for hit in finder["modrinth_search_text"](query, 12) or []:
            if finder["_titles_similar"](hit.get("title"), query):
                mr_card = finder["normalize_modrinth_hit"](hit)
                break
    except Exception:
        pass
    if api_key:
        try:
            for hit in finder["cf_bsearch"](query, api_key, 12) or []:
                if finder["_titles_similar"](hit.get("name"), query):
                    cf_slim = hit
                    break
        except Exception:
            pass
    if mr_card and not cf_slim and api_key:
        try:
            cf_slim = finder["other_on_cf"](mr_card, api_key)
        except Exception:
            pass
    elif cf_slim and not mr_card:
        try:
            mr_card = finder["mr_for_cf"](finder["normalize_cf_hit"](cf_slim), cf_slim.get("sha1"))
        except Exception:
            pass
    return mr_card, cf_slim


def _finder_resolve_local_mod(m, internet, api_key):
    if not internet:
        return
    meta = m.get("artifact_meta") if isinstance(m.get("artifact_meta"), dict) else {}
    urls = list(meta.get("links") or [])
    mr_card = cf_slim = None

    for url in urls:
        mr_card, cf_slim = _finder_lookup_metadata_url(url, api_key)
        if mr_card or cf_slim:
            _finder_apply_project_match(m, mr_card, cf_slim, api_key, "URL из JAR metadata")
            m["match_source"] = "metadata_url"
            return

    has_mr = bool(m.get("modrinth_id"))
    has_cf = bool(m.get("cf_id"))
    if has_mr != has_cf:
        targets = []
        if has_mr:
            targets.append("https://modrinth.com/mod/" + str(m["modrinth_id"]))
        if m.get("cf_slug"):
            targets.append("https://www.curseforge.com/minecraft/mc-mods/" + str(m["cf_slug"]))
        elif has_cf:
            targets.append("https://www.curseforge.com/minecraft/mc-mods/" + str(m["cf_id"]))
        for target in targets:
            mr_card, cf_slim = _finder_lookup_metadata_url(target, api_key)
            if mr_card or cf_slim:
                _finder_apply_project_match(m, mr_card, cf_slim, api_key)
                break

    names = []
    for value in (meta.get("names") or []):
        if isinstance(value, str) and value.strip() and value.strip() not in names:
            names.append(value.strip())
    manifest = meta.get("manifest") if isinstance(meta.get("manifest"), dict) else {}
    for field in ("specification-title", "implementation-title", "bundle-name"):
        value = manifest.get(field)
        if isinstance(value, str) and value.strip() and value.strip() not in names:
            names.append(value.strip())
    for value in (meta.get("modids") or []):
        if isinstance(value, str) and value.strip() and value.strip() not in names:
            names.append(value.strip())

    for name in names:
        if name.casefold() == str(m.get("display") or "").casefold():
            continue
        mr_card, cf_slim = _finder_lookup_metadata_name(name, api_key)
        if mr_card or cf_slim:
            _finder_apply_project_match(m, mr_card, cf_slim, api_key, "MANIFEST / metadata name")
            m["match_source"] = "manifest_name"
            return


# c171
def classify_mod(m, internet, api_key):
    _CLASSIFY_MOD_BASE(m, internet, api_key)
    try:
        _finder_resolve_local_mod(m, internet, api_key)
    except Exception:
        pass


def _finder_sync():
    _AUTO_FINDER["LANG"] = LANG
    _AUTO_FINDER["say"] = say
    _AUTO_FINDER["_AUDIT_TARGET_MC"] = TARGET_MC
    _AUTO_FINDER["_AUDIT_API_LOADER"] = API_LOADER


def _auto_finder_sync():
    _finder_sync()

def _auto_finder_dispatch(command, args, api_key, raw_line=""):
    _auto_finder_sync()
    handlers = {
        "search": lambda: _AUTO_FINDER["do_search"](args, api_key),
        "show": lambda: _AUTO_FINDER["do_show"](args, api_key),
        "save": lambda: _AUTO_FINDER["do_save"](args, api_key),
        "saveall": lambda: _AUTO_FINDER["do_saveall"](api_key),
        "bulk": lambda: _AUTO_FINDER["do_bulk"](args, api_key),
        "addons": lambda: _AUTO_FINDER["do_addons"](args, api_key),
        "build": lambda: _AUTO_FINDER["do_build"](args, api_key),
        "newaddons": lambda: _AUTO_FINDER["do_newaddons"](args, api_key),
        "importlink": lambda: _AUTO_FINDER["do_importlink"](args, api_key),
        "modupdate": lambda: _AUTO_FINDER["do_update"](args, api_key),
        "update": lambda: _AUTO_FINDER["do_update"](args, api_key),
    }
    handler = handlers.get(command)
    if handler is not None:
        handler()
        return True
    if command == "help":
        _do_auto_finder_help()
        return True
    if _AUTO_FINDER["is_url"](command):
        _AUTO_FINDER["do_import_urls"](raw_line or command, api_key)
        return True
    return False


def _do_auto_finder_help():
    _auto_finder_sync()
    tr = _AUTO_FINDER["T"][LANG]
    cols = shutil.get_terminal_size((100, 24)).columns
    width = max(40, min(cols, 100) - 8)
    title = "Auto-Finder — поиск и сборка модпаков" if LANG == "ru" else "Auto-Finder — mod search and modpack building"
    say()
    say(f"{GREEN}{BOLD}§ {title}{RESET}")
    rows = [
        ("search <тег|name:название|ссылка ...>", "help_search"),
        ("show <N>", "help_show"),
        ("save <N>", "help_save"),
        ("saveall", "help_saveall"),
        ("bulk <тег|name:название|ссылка ...>", "help_bulk"),
        ("addons <slug|modid>", "help_addons"),
        ("build <ссылка|slug> [загрузчик] [версия] [client|server] [mr=N] [cf=N]", "help_build"),
        ("newaddons <ссылка|slug> [период] [загрузчик] [версия]", "help_newaddons"),
        ("importlink [prefer CF|M] [min mr=N cf=N]", "help_importlink"),
        ("modupdate [версия] [загрузчик] [prefer ...] [min ...]", "help_update"),
        ("finder <команда> ...", "help_slug"),
    ]
    for command, key in rows:
        label = command
        if LANG == "en":
            labels = {
                "search <тег|name:название|ссылка ...>": "search <tag|name:title|url ...>",
                "build <ссылка|slug> [загрузчик] [версия] [mr=N] [cf=N]": "build <link|slug> [loader] [version] [mr=N] [cf=N]",
                "newaddons <ссылка|slug> [период] [загрузчик] [версия]": "newaddons <link|slug> [period] [loader] [version]",
                "importlink [prefer CF|M] [min mr=N cf=N]": "importlink [prefer CF|M] [min mr=N cf=N]",
                "modupdate [версия] [загрузчик] [prefer ...] [min ...]": "modupdate [version] [loader] [prefer ...] [min ...]",
                "finder <команда> ...": "finder <command> ...",
            }
            label = labels.get(command, command)
        desc = tr.get(key, "")
        if command == "finder <команда> ...":
            desc = ("Любую команду Auto-Finder можно вызвать с префиксом finder. Например: finder update."
                    if LANG == "ru" else
                    "Any Auto-Finder command can be called with the finder prefix. Example: finder update.")
        say()
        say(f"  {BOLD}{label}{RESET}")
        for line in help_lines(desc, width):
            say(f"    {HELP_RAIL} {line}")
    say()
    say(f"  {BOLD}key <ключ>{RESET}" if LANG == "ru" else f"  {BOLD}key <key>{RESET}")
    key_desc = tr.get("help_key", "")
    for line in help_lines(key_desc, width):
        say(f"    {HELP_RAIL} {line}")
    say()
    say(f"  {BOLD}slug{RESET}")
    for line in help_lines(tr.get("help_slug", ""), width):
        say(f"    {HELP_RAIL} {line}")


def main():
    global CONSOLE_FILE
    os.makedirs(CONSOLE_DIR, exist_ok=True)
    session_name = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S") + ".txt"
    try:
        CONSOLE_FILE = open(os.path.join(CONSOLE_DIR, session_name), "w", encoding="utf-8")
    except OSError:
        CONSOLE_FILE = None

    choose_language()
    print_banner()
    api_key = load_cf_key()
    modul_start()
    while True:
        try:
            line = input("> ").strip()
        except (EOFError, KeyboardInterrupt, ValueError):
            print()
            break
        log_console_raw(f"> {redact_for_log(line)}")
        if not line:
            continue
        parts = line.split(maxsplit=1)
        cmd = parts[0]
        rest = parts[1] if len(parts) > 1 else ""
        args = rest.split() if rest else []
        # c154
        name_args = [rest.strip()] if rest.strip() else []

        try:
            if cmd == "key" and rest:
                api_key = rest.strip()
                save_cf_key(api_key)
                NET_STATS["cf_denied"] = False
                say(f"{GREEN}{T[LANG]['key_set']}{RESET}")
            elif cmd == "run":
                run_audit(api_key)
                modul_fire("run_done")
            elif cmd == "logs":
                do_logs()
            elif cmd == "timeline":
                do_timeline()
            elif cmd == "compare":
                do_compare(args)
            elif cmd == "buildcompare":
                try:
                    do_build_compare(shlex.split(rest))
                except ValueError as parse_error:
                    say(f"{RED}{parse_error}{RESET}")
            elif cmd == "aternos":
                do_aternos()
            elif cmd == "stats":
                do_stats()
            elif cmd == "explain":
                do_explain(name_args, api_key)
            elif cmd == "disable":
                do_disable(args)
            elif cmd == "enable":
                do_enable()
            elif cmd == "rename":
                do_rename()
            elif cmd == "unrename":
                do_unrename()
            elif cmd == "remove":
                do_remove(name_args)
            elif cmd == "export":
                do_export(args)
            elif cmd == "crash":
                do_crash(args)
            elif cmd == "crashlog":
                do_crashlog()
            elif cmd == "graphic":
                do_graphic()
            elif cmd == "orphan":
                do_orphan()
            elif cmd == "scan":
                do_scan()
            elif cmd == "dupres":
                do_dupres()
            elif cmd == "clean":
                do_clean(args)
            elif cmd == "version":
                do_version(args, api_key)
            elif cmd == "updates":
                do_updates(api_key)
            elif cmd == "install":
                do_install(args, api_key)
            elif cmd == "update":
                do_update_center(rest, api_key)
            elif cmd == "report":
                do_report(api_key)
            elif cmd == "help":
                do_help()
            elif cmd == "modul":
                do_modul(args)
            elif cmd == "finder":
                try:
                    finder_parts = _AUTO_FINDER["shlex"].split(rest)
                except ValueError as parse_error:
                    say(f"{YELLOW}{parse_error}{RESET}")
                    finder_parts = []
                if finder_parts:
                    finder_cmd = finder_parts[0].lower()
                    finder_args = finder_parts[1:]
                    if finder_cmd == "key" and finder_args:
                        api_key = " ".join(finder_args).strip()
                        save_cf_key(api_key)
                        NET_STATS["cf_denied"] = False
                        say(f"{GREEN}{T[LANG]['key_set']}{RESET}")
                    elif not _auto_finder_dispatch(
                        "modupdate" if finder_cmd == "update" else finder_cmd,
                        finder_args, api_key, raw_line=rest
                    ):
                        say(T[LANG]["commands"])
                else:
                    _do_auto_finder_help()
            elif cmd in {"search", "show", "save", "saveall", "bulk", "addons",
                         "build", "newaddons", "importlink", "modupdate"}:
                try:
                    finder_args = _AUTO_FINDER["shlex"].split(rest)
                except ValueError as parse_error:
                    say(f"{YELLOW}{parse_error}{RESET}")
                    finder_args = []
                _auto_finder_dispatch(cmd, finder_args, api_key, raw_line=line)
            elif _AUTO_FINDER["is_url"](cmd):
                _auto_finder_dispatch(cmd, args, api_key, raw_line=line)
            elif cmd == "exit":
                break
            elif modul_run_command(cmd, args):
                pass
            else:
                say(T[LANG]["commands"])
        except KeyboardInterrupt:
            say(f"\n{YELLOW}{T[LANG]['cancelled']}{RESET}")  # c155
        except Exception as exc:
            log_command_crash(cmd, exc)
        modul_fire("command", cmd, args)

    modul_fire("exit")
    try:
        _auto_finder_sync()
        _AUTO_FINDER["save_cache"]()
        _AUTO_FINDER["store_flush"]()
    except Exception as exc:
        log_command_crash("auto-finder-save", exc)
    if CONSOLE_FILE:
        CONSOLE_FILE.close()

if __name__ == "__main__":
    main()