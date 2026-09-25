from datetime import datetime
import argparse
import json


def parse_logs(log_file_path):
    failed_attempts = {}

    with open(log_file_path, "r") as log_file:
        for line in log_file:
            log_line = line.strip()

            if not log_line:
                continue

            parts = log_line.split()

            if len(parts) < 4:
                continue

            timestamp = parts[0] + " " + parts[1]
            ip_address = parts[2]
            status = parts[3]

            time_object = datetime.strptime(
                timestamp,
                "%Y-%m-%d %H:%M:%S"
            )

            if status == "Login_Failed":
                if ip_address not in failed_attempts:
                    failed_attempts[ip_address] = []

                failed_attempts[ip_address].append(time_object)

    return failed_attempts


def detect_brute_force(failed_attempts):
    alerts = []

    for ip, times in failed_attempts.items():

        # Logların zaman sırası karışık olsa bile düzgün çalışsın
        times.sort()

        for i in range(len(times)):
            count = 0
            last_time = times[i]

            for j in range(i, len(times)):
                time_difference = (
                    times[j] - times[i]
                ).total_seconds()

                if time_difference <= 60:
                    count += 1
                    last_time = times[j]
                else:
                    break

            if count >= 3:

                if count >= 5:
                    severity = "HIGH"
                else:
                    severity = "MEDIUM"

                alert = {
                    "ip": ip,
                    "rule": "Brute Force Detection",
                    "severity": severity,
                    "failed_attempts": count,
                    "window_seconds": 60,
                    "start_time": str(times[i]),
                    "end_time": str(last_time)
                }

                alerts.append(alert)

                break

    return alerts


def show_alerts(alerts):
    if not alerts:
        print("\nNo suspicious activity detected.")
        return

    print("\n=== SECURITY ALERTS ===")

    for alert in alerts:
        print(
            f"[{alert['severity']}] "
            f"{alert['ip']} triggered "
            f"{alert['failed_attempts']} failed logins "
            f"within {alert['window_seconds']} seconds."
        )

        print(
            f"Time: {alert['start_time']} "
            f"-> {alert['end_time']}"
        )

        print("-" * 50)


def save_alerts(alerts, output_file="sample_alerts.json"):
    with open(output_file, "w") as file:
        json.dump(alerts, file, indent=4)

    print(f"\nAlerts saved to {output_file}")


def main():
    parser = argparse.ArgumentParser(
        description="Mini SIEM - Log Analyzer"
    )

    parser.add_argument(
        "-f",
        "--file",
        required=True,
        help="Log file to analyze"
    )

    parser.add_argument(
        "-o",
        "--output",
        default="alerts.json",
        help="JSON output file"
    )

    args = parser.parse_args()

    failed_attempts = parse_logs(args.file)

    alerts = detect_brute_force(failed_attempts)

    show_alerts(alerts)

    save_alerts(alerts, args.output)


if __name__ == "__main__":
    main()