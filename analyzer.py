from datetime import datetime
import sys
def read_log_file(file_path):
    try:
        with open(file_path, "r") as file:
            log_entries = file.readlines()

        return log_entries
    except FileNotFoundError:
        print("\nError: File not found.")
        return None


def parse_logs(log_entries):
    logs = []
    invalid_entries = 0

    for entry in log_entries:
        parts = entry.split()
        if len(parts) < 3 or parts[2] not in ["INFO", "ERROR","WARNING"]:
            invalid_entries += 1
            continue

        try:
            datetime.strptime(
                f"{parts[0]} {parts[1]}",
                "%Y-%m-%d %H:%M:%S"
            )
        except ValueError:
            invalid_entries += 1
            continue
        username = "Unknown"
        if "User" in parts:
            user_index = parts.index("User")
            username = parts[user_index + 1]

        elif "user" in parts:
            user_index = parts.index("user")
            username = parts[user_index + 1]

        log = {
            "date": parts[0],
            "time": parts[1],
            "level": parts[2],
            "message": " ".join(parts[3:]),
            "ip": parts[-1],
            "user": username
            
        }
        logs.append(log)
    return logs, invalid_entries

def analyze_logs(logs):
    info_count = 0
    error_count = 0
    warning_count = 0
    for log in logs:
        if log["level"] == "INFO":
            info_count += 1
        elif log["level"] == "ERROR":
            error_count += 1
        elif log["level"] == "WARNING":
            warning_count += 1
    return info_count, error_count, warning_count

def display_summary(logs, invalid_entries, info_count, error_count, warning_count):
    print("==========Security Analyzer==========")
    print("\nExtracting information from the log entries.....\n")
    print(f"Total log entries: {len(logs)}")
    print(f"First entry: {logs[0]['date']} {logs[0]['time']} {logs[0]['level']} {logs[0]['message']}")
    print(f"Last entry: {logs[-1]['date']} {logs[-1]['time']} {logs[-1]['level']} {logs[-1]['message']}")
    print(f"INFO Logs: {info_count}")
    print(f"ERROR Logs: {error_count}")
    print(f"WARNING Logs: {warning_count}")
    print(f"Invalid Logs: {invalid_entries}")

def detect_failed_logins(logs):
    failed_logins = []

    for log in logs:
        if "Failed login" in log["message"]:
            failed_logins.append({
                "time" : log["time"],
                "user" : log["user"],
                "ip" : log["ip"] 
            })

    return failed_logins

def analyze_failed_login_ips(failed_logins):
    ip_counts = {}

    for login in failed_logins:
        ip = login["ip"]

        if ip in ip_counts:
            ip_counts[ip] += 1
        else:
            ip_counts[ip] = 1

    return ip_counts

def detect_suspicious_ips(failed_login_ips):
    suspicious_ips = []

    for ip, count in failed_login_ips.items():
        if count >= 2:
            suspicious_ips.append({
                "ip": ip,
                "failed_attempts": count,
                "severity": "MEDIUM"
            })

    return suspicious_ips

def calculate_overall_risk(brute_force_results, suspicious_ips):
    if brute_force_results:
        return "HIGH"
    elif suspicious_ips:
        return "MEDIUM"
    else:
        return "LOW"

def analyze_severity(logs, brute_force_results):
    findings = []

    for log in logs:
        if log["level"] == "WARNING":
            findings.append({
                "severity"  : "MEDIUM",
                "message"   : "Warning event detected",
                "ip"    : log["ip"]  
            })
        elif log["level"] == "ERROR":
            findings.append({
                "severity"  : "MEDIUM",
                "message"   : "Error event detected",
                "ip"    : log["ip"]
            })

    for result in brute_force_results:
        findings.append({
            "severity"  : "HIGH",
            "message"   : "Possible brute-force attack detetcted",
            "ip"    : result["ip"],
            "failed_attempts"   : result["failed_attempts"]
        })
    return findings

def detect_brute_force(logs):
    ip_times = {}
    brute_force_results = []
    for log in logs:
        if "Failed login" in log["message"]:
            ip = log["ip"]
            time_object = datetime.strptime(log["time"], "%H:%M:%S")

            if ip not in ip_times:
                ip_times[ip] = [time_object]
            else:
                ip_times[ip].append(time_object)

    for ip, times in ip_times.items():
        times.sort()
        detected = False
        for i in range(len(times)):
            start_time = times[i]
            for j in range(i + 2, len(times)):
                time_difference = times[j] - start_time
                if time_difference.total_seconds() <= 60:

                    brute_force_results.append({
                        "ip" : ip,
                        "failed_attempts": j - i + 1
                    })

                    detected = True
                    break
            if detected:
                break
    return brute_force_results

def main():
    if len(sys.argv) > 1:
        file_path = sys.argv[1]
    else:
        file_path = input("Enter the path to the log file:")
    log_entries = read_log_file(file_path)
    if log_entries is None:
        return

    if not log_entries:
        print("Error: log file is empty")
        return
    logs, invalid_entries = parse_logs(log_entries)
    info_count, error_count, warning_count = analyze_logs(logs)
    display_summary(
        logs,
        invalid_entries,
        info_count,
        error_count,
        warning_count
    )
    failed_logins = detect_failed_logins(logs)
    failed_login_ips = analyze_failed_login_ips(failed_logins)
    suspicious_ips = detect_suspicious_ips(failed_login_ips)
    brute_force_results = detect_brute_force(logs)
    severity_findings = analyze_severity(logs, brute_force_results)

    overall_risk = calculate_overall_risk(
        brute_force_results,
        suspicious_ips
    )

    print("\nSuspicius IP Analysis")
    print("------------------------")

    for result in suspicious_ips:
        print(f"Severity: {result['severity']}")
        print(f"IP Address: {result['ip']}")
        print(f"Failed Attempts: {result['failed_attempts']}")
        print()

    print("\nSecurity Findings")
    print("-----------------------------")

    for finding in severity_findings:
        print(f"[{finding['severity']}] {finding['message']}")
        print(f"IP Address: {finding['ip']}")
        print()

    print("\nFailed Login Analysis")
    print("------------------------\n")
    for ip, count in sorted(
        failed_login_ips.items(),
        key = lambda item : item[1],
        reverse = True
    ):
        print(f"IP Address: {ip}")
        print(f"Failed Attempts: {count}")
        print()
    generate_report(
        len(log_entries),
        invalid_entries,
        info_count,
        error_count,
        warning_count,
        failed_logins,
        failed_login_ips,
        suspicious_ips,
        brute_force_results,
        severity_findings,
        overall_risk
    )

def write_failed_login_report(report, failed_logins):
    report.write("Failed Login Attempts\n")
    report.write("---------------------------------------\n")

    if failed_logins:
            for login in failed_logins:
                report.write(f"Time : {login['time']}\n")
                report.write(f"User : {login['user']}\n")
                report.write(f"IP : {login['ip']}\n")
                report.write("---------------------------------------\n\n")
    else:
        report.write("No failed logins detected\n\n")

def write_failed_login_ip_report(report, failed_login_ips):
    report.write("Failed Login Analysis by IP\n")
    report.write("----------------------------------------\n")

    if failed_login_ips:
        for ip, count in sorted(
            failed_login_ips.items(),
            key = lambda item: item[1],
            reverse = True
        ):
            report.write(f"IP Address       : {ip}\n")
            report.write(f"Failed Attempts  : {count}\n")
            report.write(f"-----------------------------------\n\n")
    else:
            report.write("No failed logins attempts detected.\n\n")

def write_security_findings_report(report, severity_findings):
    report.write("Security Findings\n")
    report.write("---------------------------------\n")

    if severity_findings:
        for finding in severity_findings:
            report.write(f"Severity         : {finding['severity']}\n")
            report.write(f"Finding          : {finding['message']}\n")
            report.write(f"IP Address       : {finding['ip']}\n")
            report.write("--------------------------------------------------\n\n")
            if "failed_attempts" in finding:
                report.write(
                    f"Failed Attempts       : {finding['failed_attempts']}\n"
                )
                report.write("--------------------------------------------------\n\n")
    else:
        report.write("No security findings detected.\n\n")

def write_suspicious_ip_report(report, suspicious_ips):
    report.write("Suspicious IP Analysis\n")
    report.write("---------------------------------------------\n")

    if suspicious_ips:
        for result in suspicious_ips:
            report.write(f"Severity     : {result['severity']}\n")
            report.write(f"IP Address   : {result['ip']}\n")
            report.write(f"Failed Attempts  : {result['failed_attempts']}\n")
            report.write("--------------------------------------------------\n\n")
    else:
        report.write("No suspicious IPs detected.\n\n")

def write_brute_force_report(report, brute_force_results):
            report.write("Brute Force Detection\n")
            report.write("---------------------------------------\n")
            
            if brute_force_results:
                    for result in brute_force_results:
                        report.write("Possible Brute Force Attack\n")
                        report.write(f"IP Address       : {result['ip']}\n")
                        report.write(f"Failed Attempts  : {result['failed_attempts']}\n")
                        report.write("---------------------------------------\n")
            else:
                report.write("No Brute Force Attacks Detected.\n")
def generate_report(total_log_entries, invalid_entries, info_count, error_count, warning_count, failed_logins, failed_login_ips, suspicious_ips, brute_force_results, severity_findings, overall_risk):
    with open("security_report.txt", "w") as report:
        report.write("\n============= Security Log Analyzer =================\n")
        report.write("Security Assessment\n")
        report.write("----------------------------------------------------------\n")
        report.write(
            f"Report generated  : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
        )
        report.write(f"Overall Risk     : {overall_risk}\n")
        report.write("-----------------------------------------------------------\n\n")
        report.write("Summary\n")
        report.write("----------------------------------------------\n")
        report.write(f"Total Log Entries    : {total_log_entries}\n")
        report.write(f"Valid Log Entries    : {total_log_entries - invalid_entries}\n")
        report.write(f"Invalid Logs         : {invalid_entries}\n")
        report.write(f"INFO Logs            : {info_count}\n")
        report.write(f"ERROR Logs           : {error_count}\n")
        report.write(f"WARNING Logs         : {warning_count}\n")
        report.write("----------------------------------------------\n\n")
        write_failed_login_report(report, failed_logins)
        write_failed_login_ip_report(report, failed_login_ips)
        write_suspicious_ip_report(report, suspicious_ips)
        write_security_findings_report(report, severity_findings)
        write_brute_force_report(report, brute_force_results)
        
if __name__ == "__main__":
    main()