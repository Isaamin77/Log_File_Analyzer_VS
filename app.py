import streamlit as st
import pandas as pd
import re
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import LabelEncoder

st.set_page_config(page_title="Log File Analyzer", layout="wide")
st.title("Log File Analyzer")

# File uploader
uploaded_file = st.file_uploader("Upload an access log file", type=["txt", "log"])

# Extract logs using regex
def extract_logs(lines):
    ip_list, method_list, url_list, status_list = [], [], [], []
    for line in lines:
        ip = re.search(r'^\d+\.\d+\.\d+\.\d+', line)
        method_url = re.search(r'"(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH) (.*?) HTTP', line)
        status = re.search(r'" (\d{3}) ', line)

        ip_list.append(ip.group() if ip else None)
        method_list.append(method_url.group(1) if method_url else None)
        url_list.append(method_url.group(2) if method_url else None)
        status_list.append(status.group(1) if status else None)

    df = pd.DataFrame({
        'IP Address': ip_list,
        'HTTP Method': method_list,
        'URL': url_list,
        'Status Code': status_list
    })

    return df.dropna()

# Main logic
if uploaded_file is not None:
    lines = uploaded_file.read().decode("utf-8").splitlines()
    df_clean = extract_logs(lines)

    # --- Anomaly Detection ---
    df_ml = df_clean.copy()
    le_ip = LabelEncoder()
    le_method = LabelEncoder()
    le_status = LabelEncoder()

    df_ml['IP_Encoded'] = le_ip.fit_transform(df_ml['IP Address'])
    df_ml['Method_Encoded'] = le_method.fit_transform(df_ml['HTTP Method'])
    df_ml['Status_Encoded'] = le_status.fit_transform(df_ml['Status Code'])

    features = df_ml[['IP_Encoded', 'Method_Encoded', 'Status_Encoded']]
    model = IsolationForest(contamination=0.01, random_state=42)
    df_clean['Anomaly'] = model.fit_predict(features).tolist()
    df_clean['Anomaly'] = df_clean['Anomaly'].map({1: 0, -1: 1})  # 1 = anomaly

    st.success("Log file successfully parsed and analyzed.")

    # --- SIDEBAR FILTERS ---
    st.sidebar.header("Filter Data")
    ip_filter = st.sidebar.multiselect("IP Address", df_clean["IP Address"].unique())
    method_filter = st.sidebar.multiselect("HTTP Method", df_clean["HTTP Method"].unique())
    status_filter = st.sidebar.multiselect("Status Code", df_clean["Status Code"].unique())
    url_filter = st.sidebar.multiselect("URL", df_clean["URL"].unique())
    anomalies_only = st.sidebar.checkbox("Show Anomalies Only")

    # --- APPLY FILTERS ---
    df_filtered = df_clean.copy()
    if ip_filter:
        df_filtered = df_filtered[df_filtered["IP Address"].isin(ip_filter)]
    if method_filter:
        df_filtered = df_filtered[df_filtered["HTTP Method"].isin(method_filter)]
    if status_filter:
        df_filtered = df_filtered[df_filtered["Status Code"].isin(status_filter)]
    if url_filter:
        df_filtered = df_filtered[df_filtered["URL"].isin(url_filter)]
    if anomalies_only:
        df_filtered = df_filtered[df_filtered["Anomaly"] == 1]

    # --- DISPLAY RESULTS ---
    st.write("### Filtered Data")
    st.dataframe(df_filtered, use_container_width=True)

    st.write("### Top 5 IP Addresses")
    st.bar_chart(df_filtered['IP Address'].value_counts().head(5))

    st.write("### Top 5 Requested URLs")
    st.bar_chart(df_filtered['URL'].value_counts().head(5))

    st.write("### Status Code Distribution")
    st.line_chart(df_filtered['Status Code'].value_counts())

    st.write("### HTTP Method Distribution")
    st.bar_chart(df_filtered['HTTP Method'].value_counts())

    # --- DOWNLOAD ---
    st.download_button(
        label="Download Filtered CSV",
        data=df_filtered.to_csv(index=False).encode(),
        file_name="filtered_logs.csv",
        mime="text/csv"
    )

else:
    st.info("Please upload a log file to begin.")
