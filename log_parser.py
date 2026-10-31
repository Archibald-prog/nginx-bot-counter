import re
from pathlib import Path
from collections import Counter

LOG_FILE = Path("/var/log/nginx/access.log")
REPORT_FILE = Path(__file__).resolve().parent / "ip_blacklist.txt"

ACCESS_PATTERN = (
    r"^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}).*?\".*?\"\s+(404)\s+"
)


def count_bot_ip(log, report, reg_pattern):
    if not log.exists():
        print(
            f"Ошибка: Файл {log.name} не найден. Проверьте путь."
        )
        return

    print(f"Запуск анализатора живых логов: {log.name}")

    ip_counter = Counter()

    try:
        with open(log, "r", encoding="utf-8") as file:
            for line in file:
                match = re.search(reg_pattern, line)
                if match:
                    ip_address = match.group(1)
                    ip_counter[ip_address] += 1

    except PermissionError:
        print(
            f"Ошибка доступа: запустите скрипт через sudo: "
            f"sudo python3 {Path(__file__).name}"
        )
        import sys

        sys.exit(1)

    if not ip_counter:
        print(
            "Аномальные запросы со статусом 404 "
            "в логе не обнаружены."
        )
    else:
        print(
            f"Анализ завершен. "
            f"Выявлено ботов-сканеров: {len(ip_counter)}"
        )

        with open(report, "w", encoding="utf-8") as out_file:
            out_file.write(
                "=== ЧЕРНЫЙ СПИСОК БОТОВ (СТАТУС 404) ===\n"
            )
            for ip, count in ip_counter.most_common():
                line_text = f"IP: {ip:<16} | Ошибок 404: {count}\n"
                print(f"{line_text.strip()}")
                out_file.write(line_text)

        print(
            f"Черный список успешно обновлен на сервере: "
            f"{report.name}"
        )


if __name__ == '__main__':
    count_bot_ip(LOG_FILE, REPORT_FILE, ACCESS_PATTERN)
    