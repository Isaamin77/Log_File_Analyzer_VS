import re
import sqlite3
import time

#Connects to the existing SQLite database
conn = sqlite3.connect('log_data.db')
cursor = conn.cursor()

#Function to extract log components from a single line
def extract_log_info(line):
    ip = re.search(r'^\d+\.\d+\.\d+\.\d+', line)
    method_url = re.search(r'"(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH) (.*?) HTTP', line)
    status = re.search(r'" (\d{3}) ', line)

    return (
        ip.group() if ip else None,
        method_url.group(1) if method_url else None,
        method_url.group(2) if method_url else None,
        status.group(1) if status else None
    )

#Opens the log file
with open("access.log.txt", "r") as file:
    for line in file:
        ip, method, url, status = extract_log_info(line)

        if None not in (ip, method, url, status):
            try:
                cursor.execute("""
                    INSERT INTO logs (ip_address, http_method, url, status_code)
                    VALUES (?, ?, ?, ?)
                """, (ip, method, url, status))
                conn.commit()
                print(f"[INSERTED] {ip} {method} {url} {status}")
            except Exception as e:
                print(f"[DB ERROR] Could not insert log: {e}")
        else:
            print(f"[SKIPPED] Incomplete log entry: {line.strip()}")

        time.sleep(1)  # Simulating real time delay 

conn.close()
print("Real-time simulation complete.")
