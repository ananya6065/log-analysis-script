import re
import csv
from collections import defaultdict


def count_requests_per_ip(log_lines):
    ip_count = defaultdict(int)
    for line in log_lines:
        match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
        if match:
            ip = match.group(1)
            ip_count[ip] += 1
    return dict(ip_count)


def most_accessed_endpoint(log_lines):
    endpoint_count = defaultdict(int)
    for line in log_lines:
        match = re.search(r'"(GET|POST) (.+?) ', line)
        if match:
            endpoint = match.group(2)
            endpoint_count[endpoint] += 1
    most_accessed = max(endpoint_count.items(), key=lambda x: x[1], default=(None, 0))
    return most_accessed


def detect_suspicious_activity(log_lines, threshold=1):
    failed_logins = defaultdict(int)

    for line in log_lines:
        if '401' in line and 'Invalid credentials' in line:
            match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
            if match:
                ip = match.group(1)
                failed_logins[ip] += 1

    suspicious_ips = {ip: count for ip, count in failed_logins.items() if count > threshold}
    return suspicious_ips


def main():
    with open('sample.log', 'r') as file:
        log_lines = file.readlines()

    # Count requests per IP
    ip_counts = count_requests_per_ip(log_lines)
    print("IP Address           Request Count")
    for ip, count in ip_counts.items():
        print(f"{ip:<20} {count}")

    # Most accessed endpoint
    endpoint, access_count = most_accessed_endpoint(log_lines)
    print(f"\nMost Frequently Accessed Endpoint:\n{endpoint} (Accessed {access_count} times)")

    # Detect suspicious activity
    suspicious_activity = detect_suspicious_activity(log_lines, threshold=1)  # Set threshold to 1 for testing
    print("\nSuspicious Activity Detected:")
    print("IP Address           Failed Login Attempts")
    for ip, count in suspicious_activity.items():
        print(f"{ip:<20} {count}")

    # Save results to CSV
    with open('log_analysis_results.csv', 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)

        # Write Requests per IP section
        writer.writerow(['IP Address', 'Request Count'])
        for ip, count in ip_counts.items():
            writer.writerow([ip, count])

        # Write a blank line for separation
        writer.writerow([])

        # Write Most Accessed Endpoint section
        writer.writerow(['Endpoint', 'Access Count'])
        writer.writerow([endpoint, access_count])

        # Write a blank line for separation
        writer.writerow([])

        # Write Suspicious Activity section
        writer.writerow(['IP Address', 'Failed Login Count'])
        for ip, count in suspicious_activity.items():
            writer.writerow([ip, count])


if __name__ == "__main__":
    main()