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

    for entry in log_entries:
        parts = entry.split()
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
    return logs

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

def display_summary(log_entries, info_count, error_count, warning_count):
    print("==========Security Analyzer==========")
    print("\nExtracting information from the log entries.....\n")
    print(f"Total log entries: {len(log_entries)}")
    print(f"First entry: {log_entries[0].strip()}")
    print(f"Last entry: {log_entries[-1].strip()}")
    print(f"INFO Logs: {info_count}")
    print(f"ERROR Logs: {error_count}")
    print(f"WARNING Logs: {warning_count}")

def detect_failed_logins(logs):
    print("\n==========Failed Login Report==========\n")
    found = False

    for log in logs:
        if "Failed login" in log["message"]:

            found = True

            print(f"Time : {log['time']}")
            print(f"User : {log['user']}")
            print(f"IP : {log['ip']}")
            print("----------------------------------------------")
    if not found:
        print("No failed logins detected")

def detect_brute_force(logs):
    ip_counter = {}
    for log in logs:
        if "Failed login" in log["message"]:
            ip = log["ip"]
            if ip not in ip_counter:
                ip_counter[ip] = 1
            else:
                ip_counter[ip] += 1
    print("\n========== Brute Force Detection ==========\n")
    found = False
    for ip, count in ip_counter.items():
        if count >= 3:
            found = True
            print("Possible Brute Force Attack")
            print(f"IP Address      : {ip}")
            print(f"Failed Attempts : {count}")
            print("---------------------------------------")
    if not found:
        print("No brute force attack detected.")

def main():
    file_path = input("Enter the path to the log file:")
    log_entries = read_log_file(file_path)
    if log_entries is None:
        return
    logs = parse_logs(log_entries)
    info_count, error_count, warning_count = analyze_logs(logs)
    display_summary(
        log_entries,
        info_count,
        error_count,
        warning_count
    )
    detect_failed_logins(logs)
    detect_brute_force(logs)

if __name__ == "__main__":
    main()