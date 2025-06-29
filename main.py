import re
import pandas as pd
import matplotlib.pyplot as plt
import sqlite3
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import LabelEncoder

#Load the log file
with open("access.log.txt", "r") as file:
    logs = file.readlines()

#Extract data using regex
ip_list = []
method_list = []
url_list = []
status_list = []

for line in logs:
    ip = re.search(r'^\d+\.\d+\.\d+\.\d+', line)
    method_url = re.search(r'"(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH) (.*?) HTTP', line)
    status = re.search(r'" (\d{3}) ', line)

    ip_list.append(ip.group() if ip else None)
    method_list.append(method_url.group(1) if method_url else None)
    url_list.append(method_url.group(2) if method_url else None)
    status_list.append(status.group(1) if status else None)

#Create DataFrame
df = pd.DataFrame({
    'IP Address': ip_list,
    'HTTP Method': method_list,
    'URL': url_list,
    'Status Code': status_list
})

#Clean the DataFrame
df_clean = df.dropna(subset=['HTTP Method', 'URL', 'Status Code'])

# --- Anomaly Detection with Isolation Forest ---
le_method = LabelEncoder()
le_status = LabelEncoder()
le_ip = LabelEncoder()

df_ml = df_clean.copy()
df_ml['Method_Encoded'] = le_method.fit_transform(df_ml['HTTP Method'])
df_ml['Status_Encoded'] = le_status.fit_transform(df_ml['Status Code'])
df_ml['IP_Encoded'] = le_ip.fit_transform(df_ml['IP Address'])

features = df_ml[['Method_Encoded', 'Status_Encoded', 'IP_Encoded']]
iso_forest = IsolationForest(contamination=0.01, random_state=42)
df_ml['Anomaly'] = iso_forest.fit_predict(features)
df_ml['Anomaly'] = df_ml['Anomaly'].map({1: 0, -1: 1})  # 1 = anomaly

df_clean['Anomaly'] = df_ml['Anomaly']
df_clean.to_csv("cleaned_log_data.csv", index=False)
df_clean[df_clean['Anomaly'] == 1].to_csv("anomalies.csv", index=False)

#Analyze
status_counts = df_clean['Status Code'].value_counts()
method_counts = df_clean['HTTP Method'].value_counts()
top_ips = df_clean['IP Address'].value_counts().head(5)
top_urls = df_clean['URL'].value_counts().head(5)

print("\n Top 5 IP addresses:")
print(top_ips)

print("\n Top 5 requested URLs:")
print(top_urls)

print("\n HTTP method distribution:")
print(method_counts)

print("\n Status code distribution:")
print(status_counts)

#Top 5 IPs
plt.figure(figsize=(8,5))
top_ips.plot(kind='bar')
plt.title('Top 5 IP Addresses')
plt.xlabel('IP Address')
plt.ylabel('Number of Requests')
plt.xticks(rotation=45)
plt.tight_layout()
plt.savefig("top_ips_bar.png")
plt.close()

#Top 5 URLs
plt.figure(figsize=(8,5))
top_urls.plot(kind='bar')
plt.title('Top 5 Requested URLs')
plt.xlabel('URL')
plt.ylabel('Number of Requests')
plt.xticks(rotation=45, ha='right')
plt.tight_layout()
plt.savefig("top_urls_bar.png")
plt.close()

#Status code line chart
plt.figure(figsize=(8,5))
plt.plot(status_counts.index, status_counts.values, marker='o', linestyle='-')
plt.title('Status Code Distribution')
plt.xlabel('Status Code')
plt.ylabel('Number of Requests')
plt.grid(True)
plt.tight_layout()
plt.savefig("status_codes_line.png")
plt.close()

#HTTP method bar chart
plt.figure(figsize=(8,5))
ax = method_counts.plot(kind='bar')
plt.title('HTTP Method Distribution')
plt.xlabel('HTTP Method')
plt.ylabel('Number of Requests')

for p in ax.patches:
    ax.annotate(str(p.get_height()), (p.get_x() + p.get_width() / 2, p.get_height()),
                ha='center', va='bottom')

plt.tight_layout()
plt.savefig("http_methods_bar.png")
plt.close()

#Save cleaned data
df_clean.to_csv("cleaned_log_data.csv", index=False)

#Store into SQLite database
conn = sqlite3.connect('log_data.db')
cursor = conn.cursor()

cursor.execute("""
CREATE TABLE IF NOT EXISTS logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip_address TEXT,
    http_method TEXT,
    url TEXT,
    status_code TEXT
)
""")

for _, row in df_clean.iterrows():
    cursor.execute("""
        INSERT INTO logs (ip_address, http_method, url, status_code)
        VALUES (?, ?, ?, ?)
    """, (row['IP Address'], row['HTTP Method'], row['URL'], row['Status Code']))

conn.commit()

#Sample query from the DB
print("\n📋 Top 5 IPs (queried from database):")
cursor.execute("""
    SELECT ip_address, COUNT(*) as total
    FROM logs
    GROUP BY ip_address
    ORDER BY total DESC
    LIMIT 5
""")
for row in cursor.fetchall():
    print(f"{row[0]} → {row[1]} requests")

conn.close()

print("Charts and CSV saved in the project folder.")
