
import re
import os
import argparse
from collections import Counter
from pathlib import Path
import requests


def analyze_log(log_file, threshold):
    path = Path(log_file)

    if not path.exists():
        print(f"Файл не найден: {log_file}")
        return

    pattern = re.compile(
        r'^(\S+)\s+\S+\s+\S+\s+\[[^\]]+\]\s+"[^"]*"\s+(\d{3})'
    )

    ip_errors = Counter()

    with path.open("r", encoding="utf-8", errors="replace") as file:
        for line in file:
            match = pattern.search(line)

            if match:
                ip = match.group(1)
                status = match.group(2)

                if status == "404":
                    ip_errors[ip] += 1

    print("\nРезультаты анализа логов:")

    suspicious = []

    for ip, count in ip_errors.most_common():
        print(f"IP: {ip} | Ошибок 404: {count}")

        if count > threshold:
            suspicious.append((ip, count))

    if not suspicious:
        print("\nПодозрительная активность не обнаружена.")
        return

    print("\nОбнаружена подозрительная активность!")

    for ip, count in suspicious:
        message = (
            f"Обнаружена подозрительная активность!\n"
            f"IP-адрес: {ip}\n"
            f"Количество ошибок 404: {count}"
        )

        print(message)
        send_telegram(message)


def send_telegram(message):
    token = os.getenv("TELEGRAM_TOKEN")
    chat_id = os.getenv("CHAT_ID")

    if not token or not chat_id:
        print("Telegram не настроен. Уведомление не отправлено.")
        return

    url = f"https://api.telegram.org/bot{token}/sendMessage"

    try:
        response = requests.post(
            url,
            json={"chat_id": chat_id, "text": message},
            timeout=10
        )
        response.raise_for_status()

        if response.json().get("ok"):
            print("Уведомление отправлено в Telegram.")
        else:
            print("Telegram не подтвердил отправку.")

    except requests.RequestException as error:
        print(f"Ошибка отправки: {error}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Анализ логов Nginx"
    )

    parser.add_argument("--log", default="access.log")
    parser.add_argument("--threshold", type=int, default=50)

    args = parser.parse_args()

    analyze_log(args.log, args.threshold)
