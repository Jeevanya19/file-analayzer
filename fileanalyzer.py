
import re
from collections import Counter


def parse_log_line(line):
    pattern = r'(\S+) \S+ \S+ \[.*?\] "(.*?)" (\d{3})'

    match = re.search(pattern, line)

    if match:
        ip = match.group(1)
        request = match.group(2)
        status_code = int(match.group(3))

        endpoint = request.split()[1] if len(request.split()) > 1 else "Unknown"

        return ip, status_code, endpoint

    return None


def analyze_log(filename):
    ip_count = Counter()
    endpoint_count = Counter()

    total_requests = 0
    error_count = 0
    malformed_count = 0

    try:
        with open(filename, "r") as file:
            for line in file:
                result = parse_log_line(line)

                if result is None:
                    malformed_count += 1
                    continue

                ip, status, endpoint = result

                total_requests += 1
                ip_count[ip] += 1
                endpoint_count[endpoint] += 1

                if status >= 400:
                    error_count += 1

        print("\n========== LOG ANALYSIS REPORT ==========")

        print("Total Requests:", total_requests)
        print("Error Responses:", error_count)
        print("Malformed Lines:", malformed_count)

        print("\nTop IP Addresses:")
        for ip, count in ip_count.most_common(5):
            print(ip, ":", count, "requests")

        print("\nMost Requested Endpoints:")
        for endpoint, count in endpoint_count.most_common(5):
            print(endpoint, ":", count, "requests")

        print("\n=========================================")

    except FileNotFoundError:
        print("Error: Log file not found!")


analyze_log("server.log")
