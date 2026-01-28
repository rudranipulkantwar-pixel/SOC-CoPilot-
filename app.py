import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import os

from modules.elastic_client import fetch_latest_logs
from modules.log_parser import extract_platform_from_log, extract_timestamp_from_log
from modules.severity_engine import call_ollama
from modules.llm_engine import generate_summary_and_mitigation
from modules.langchain_pipeline import analyze_log
from modules.mitre_engine import detect_mitre_attack, format_mitre_for_ui

# ---------------- PAGE CONFIG ----------------
st.set_page_config(
    page_title="SOC Analyst Dashboard",
    layout="wide",
    page_icon="🛡️"
)

# ---------------- HEADER ----------------
st.markdown(
    """
    <h1 style='text-align:center;'>🛡️ SOC Analyst Dashboard</h1>
    <h4 style='text-align:center;'>AI-Driven Log, Incident & Threat Analysis</h4>
    """,
    unsafe_allow_html=True
)
st.divider()

# ---------------- LOAD LOGS ----------------
df_logs = pd.DataFrame()  # safe initialization

try:
    logs = fetch_latest_logs(size=500)
    df_logs = pd.DataFrame(logs) if logs else pd.read_csv("output/llm_output/enriched_logs.csv")
except Exception:
    try:
        df_logs = pd.read_csv("output/llm_output/enriched_logs.csv")
    except FileNotFoundError:
        st.warning("No logs found. Upload a folder to start.")
        df_logs = pd.DataFrame(columns=["log"])  # empty dataframe with 'log' column

# ---------------- FOLDER UPLOAD ----------------
st.subheader("📂 Upload Logs Folder (CSV/JSON files)")

uploaded_files = st.file_uploader(
    "Select multiple log files",
    type=["csv", "json"],
    accept_multiple_files=True
)

if uploaded_files:
    st.info(f"{len(uploaded_files)} files uploaded")
    new_logs = []

    for uploaded_file in uploaded_files:
        try:
            if uploaded_file.name.endswith(".csv"):
                df = pd.read_csv(uploaded_file)
            elif uploaded_file.name.endswith(".json"):
                df = pd.read_json(uploaded_file)
            else:
                st.warning(f"Skipped unsupported file: {uploaded_file.name}")
                continue

            if "log" in df.columns:
                new_logs.append(df)
            else:
                st.warning(f"'log' column not found in {uploaded_file.name}, skipping")
        except Exception as e:
            st.error(f"Failed to read {uploaded_file.name}: {e}")

    if new_logs:
        df_new_logs = pd.concat(new_logs, ignore_index=True)

        # Enrich new logs
        if "platform" not in df_new_logs.columns:
            df_new_logs["platform"] = df_new_logs["log"].apply(extract_platform_from_log)
        if "timestamp" not in df_new_logs.columns:
            df_new_logs["timestamp"] = df_new_logs["log"].apply(extract_timestamp_from_log)

        df_new_logs["timestamp"] = pd.to_datetime(df_new_logs["timestamp"], errors="coerce")

        # Append to existing logs
        df_logs = pd.concat([df_logs, df_new_logs], ignore_index=True)

        st.success(f"New logs added! Total logs: {len(df_logs)}")

# ---------------- ENRICH LOGS ----------------
if not df_logs.empty:
    if "platform" not in df_logs.columns:
        df_logs["platform"] = df_logs["log"].apply(extract_platform_from_log)

    if "timestamp" not in df_logs.columns:
        df_logs["timestamp"] = df_logs["log"].apply(extract_timestamp_from_log)

    df_logs["timestamp"] = pd.to_datetime(df_logs["timestamp"], errors="coerce")

# ---------------- ENRICH LOGS ----------------
if not df_logs.empty:

    if "platform" not in df_logs.columns:
        df_logs["platform"] = df_logs["log"].apply(extract_platform_from_log)

    if "timestamp" not in df_logs.columns:
        df_logs["timestamp"] = df_logs["log"].apply(extract_timestamp_from_log)

    df_logs["timestamp"] = pd.to_datetime(df_logs["timestamp"], errors="coerce")

    if "severity" not in df_logs.columns:
        df_logs["severity"] = "INFO"

    if "severity_number" not in df_logs.columns:
        df_logs["severity_number"] = 0

# ---------------- METRICS ----------------
c1, c2, c3, c4, c5 = st.columns(5)
c1.metric("📄 Logs", len(df_logs))
c2.metric("🟢 Low", len(df_logs[df_logs["severity_number"] == 1]))
c3.metric("🟡 Medium+", len(df_logs[df_logs["severity_number"] >= 2]))
c4.metric("🔴 High+", len(df_logs[df_logs["severity_number"] >= 3]))
c5.metric("💬 Info", len(df_logs[df_logs["severity_number"] == 0]))
st.divider()

# ---------------- DATE FILTER ----------------
st.subheader("📅 Date Range Filter")
if not df_logs.empty and df_logs["timestamp"].notna().any():
    date_range = st.date_input(
        "Select range",
        [df_logs["timestamp"].min().date(), df_logs["timestamp"].max().date()]
    )

    df_logs = df_logs[
        (df_logs["timestamp"].dt.date >= date_range[0]) &
        (df_logs["timestamp"].dt.date <= date_range[1])
    ]


#=======================================================================
#=======================================================================
st.subheader("🚨 SOC Severity Overview")

# ---------- PREP DATA ----------
sev_order = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
sev_colors = {
    "INFO": "#4DA3FF",
    "LOW": "#2ECC71",
    "MEDIUM": "#F1C40F",
    "HIGH": "#E67E22",
    "CRITICAL": "#E74C3C"
}

df_logs["severity"] = df_logs["severity"].fillna("INFO")

# ---------- METRIC + DONUT ----------
c1, c2 = st.columns([1, 2])

with c1:
    st.metric("Total Events", len(df_logs))

with c2:
    sev_count = (
        df_logs["severity"]
        .value_counts()
        .reindex(sev_order, fill_value=0)
        .reset_index()
    )
    sev_count.columns = ["Severity", "Count"]

    donut_fig = go.Figure(
        data=[
            go.Pie(
                labels=sev_count["Severity"],
                values=sev_count["Count"],
                hole=0.55,
                marker=dict(colors=[sev_colors[s] for s in sev_count["Severity"]]),
                textinfo="percent+label"
            )
        ]
    )

    donut_fig.update_layout(
        title="Severity Distribution",
        showlegend=False,
        margin=dict(t=40, b=0, l=0, r=0)
    )

    st.plotly_chart(donut_fig, use_container_width=True)

# ---------- SEVERITY OVER TIME (STACKED) ----------
st.markdown("### ⏱ Events Over Time")

time_df = (
    df_logs
    .dropna(subset=["timestamp"])
    .groupby([df_logs["timestamp"].dt.floor("5min"), "severity"])
    .size()
    .reset_index(name="count")
)

fig = go.Figure()

for sev in sev_order:
    sev_data = time_df[time_df["severity"] == sev]
    fig.add_bar(
        x=sev_data["timestamp"],
        y=sev_data["count"],
        name=sev,
        marker_color=sev_colors[sev]
    )

fig.update_layout(
    barmode="stack",
    xaxis_title="Time",
    yaxis_title="Event Count",
    legend_title="Severity",
    height=400
)

st.plotly_chart(fig, use_container_width=True)
#============================================================================
#=============================================================================
st.subheader("🧠 Advanced SOC Severity Intelligence")

# ---------- CONFIG ----------
sev_weights = {
    "INFO": 0,
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4
}

sev_colors = {
    "INFO": "#4DA3FF",
    "LOW": "#2ECC71",
    "MEDIUM": "#F1C40F",
    "HIGH": "#E67E22",
    "CRITICAL": "#E74C3C"
}

df_logs["severity"] = df_logs["severity"].fillna("INFO")
df_logs["sev_weight"] = df_logs["severity"].map(sev_weights)

# ---------- TIME INTERVAL SELECTOR ----------
c1, c2 = st.columns([1, 3])
with c1:
    interval = st.selectbox(
        "Aggregation Window",
        ["5min", "15min", "1H"],
        index=0
    )

# ---------- AGGREGATE ----------
time_agg = (
    df_logs
    .dropna(subset=["timestamp"])
    .groupby([df_logs["timestamp"].dt.floor(interval), "severity"])
    .size()
    .reset_index(name="count")
)

# ---------- SPIKE DETECTION ----------
st.markdown("### 🔔 Severity Spike Detection")

recent_window = time_agg["timestamp"].max()
baseline = time_agg[time_agg["timestamp"] < recent_window]

alerts = []

for sev in ["HIGH", "CRITICAL"]:
    recent_count = time_agg[
        (time_agg["timestamp"] == recent_window) &
        (time_agg["severity"] == sev)
    ]["count"].sum()

    baseline_avg = baseline[
        baseline["severity"] == sev
    ]["count"].mean()

    if baseline_avg and recent_count > baseline_avg * 1.5:
        alerts.append(f"🚨 {sev} spike detected: {recent_count} vs avg {int(baseline_avg)}")

if alerts:
    for a in alerts:
        st.error(a)
else:
    st.success("No abnormal HIGH / CRITICAL spikes detected")

# ---------- STACKED TIMELINE ----------
st.markdown("### ⏱ Severity Timeline (Stacked)")

fig = go.Figure()
for sev in sev_colors:
    sev_df = time_agg[time_agg["severity"] == sev]
    fig.add_bar(
        x=sev_df["timestamp"],
        y=sev_df["count"],
        name=sev,
        marker_color=sev_colors[sev]
    )

fig.update_layout(
    barmode="stack",
    height=380,
    xaxis_title="Time",
    yaxis_title="Event Count"
)

st.plotly_chart(fig, use_container_width=True)

# ---------- PLATFORM RISK VIEW ----------
st.markdown("### 🧭 Platform-Wise Severity Distribution")

plat_df = (
    df_logs
    .groupby(["platform", "severity"])
    .size()
    .reset_index(name="count")
)

fig = px.bar(
    plat_df,
    x="platform",
    y="count",
    color="severity",
    color_discrete_map=sev_colors
)

fig.update_layout(height=350)
st.plotly_chart(fig, use_container_width=True)

# ---------- RISK SCORE ----------
st.markdown("### 🎯 Unified Risk Score")

risk_score = int(
    (df_logs["sev_weight"].sum() /
     max(len(df_logs), 1)) * 25
)
risk_score = min(risk_score, 100)

if risk_score >= 75:
    st.error(f"🔴 HIGH RISK — {risk_score}/100")
elif risk_score >= 50:
    st.warning(f"🟠 MEDIUM RISK — {risk_score}/100")
else:
    st.success(f"🟢 LOW RISK — {risk_score}/100")

st.progress(risk_score / 100)

# ---------- ANOMALY OVERLAY ----------
st.markdown("### 🧪 Event Volume Anomaly Detection")

# Example interval: "1H" for hourly, "30min", etc.
interval = "1H"

volume_df = (
    df_logs
    .groupby(df_logs["timestamp"].dt.floor(interval))
    .size()
    .reset_index(name="count")
)

volume_df["baseline"] = volume_df["count"].rolling(5).mean()

fig = go.Figure()

# Current line
fig.add_trace(go.Scatter(
    x=volume_df["timestamp"],
    y=volume_df["count"],
    mode="lines+markers",
    name="Current",
    line=dict(color="cyan")
))

# Baseline line
fig.add_trace(go.Scatter(
    x=volume_df["timestamp"],
    y=volume_df["baseline"],
    mode="lines",
    name="Baseline",
    line=dict(color="gray", dash="dash")
))

fig.update_layout(
    height=300,
    xaxis_title="Timestamp",
    yaxis_title="Event Count",
    legend=dict(orientation="h", y=-0.2)
)

st.plotly_chart(fig, use_container_width=True)


# ---------------- VISUALIZATIONS ----------------
st.subheader("📊 Severity Distribution")
sev_df = df_logs["severity"].value_counts().reset_index()
sev_df.columns = ["Severity", "Count"]
st.plotly_chart(px.bar(sev_df, x="Severity", y="Count", color="Severity"),
                use_container_width=True)

st.subheader("📈 Platform vs Severity")
plat_df = df_logs.groupby(["platform", "severity"]).size().reset_index(name="count")
st.plotly_chart(px.bar(plat_df, x="platform", y="count", color="severity"),
                use_container_width=True)

st.subheader("⏱ Incident Timeline")
time_df = df_logs.groupby(
    [df_logs["timestamp"].dt.floor("H"), "severity"]
).size().reset_index(name="count")
st.plotly_chart(px.line(time_df, x="timestamp", y="count", color="severity"),
                use_container_width=True)



# ======================================================
# 🧠 LLM TIMESTAMP-WISE TIMELINE EXPLANATION (FIXED)
# ======================================================
# ======================================================
# 🧠 STRICT TIMESTAMP-WISE TIMELINE EXPLANATION
# ======================================================
st.subheader("🧠 Timeline Explanation (LLM Generated)")
st.caption("Each timestamp is explained individually based on event volume")

timeline_df = (
    df_logs
    .dropna(subset=["timestamp"])
    .groupby(df_logs["timestamp"].dt.floor("H"))
    .size()
    .reset_index(name="count")
    .sort_values("timestamp")
)

avg_events = timeline_df["count"].mean()

def fallback_explanation(ts, count):
    if count > avg_events * 2:
        return "Sharp spike in events, possible attack or anomaly"
    elif count > avg_events * 1.3:
        return "Noticeable increase, requires monitoring"
    elif count < avg_events * 0.5:
        return "Low activity period, system mostly idle"
    else:
        return "Normal baseline system activity"

if st.button("▶ Generate Timeline Explanation"):
    with st.spinner("🧠 Analyzing timeline..."):

        timeline_context = "\n".join([
            f"{row['timestamp'].strftime('%H:%M')} | {row['count']}"
            for _, row in timeline_df.iterrows()
        ])

        prompt = f"""
You are a SOC analyst.

Return ONLY timestamp-wise explanations.
DO NOT write paragraphs.
DO NOT summarize the day.
DO NOT add mitigation steps.

MANDATORY OUTPUT FORMAT:
HH:MM - short explanation

Timeline data:
{timeline_context}

If you do not follow the format, the response is invalid.
"""

        response = generate_summary_and_mitigation(prompt, "INFO")
        raw = response.get("summary", "").strip()

    st.markdown("### 🕒 Timeline Transcript")

    valid_lines = []

    for line in raw.split("\n"):
        if ":" in line and "-" in line:
            valid_lines.append(line.strip())

    # 🔁 Fallback if LLM still misbehaves
    if len(valid_lines) < len(timeline_df) / 2:
        for _, row in timeline_df.iterrows():
            ts = row["timestamp"].strftime("%H:%M")
            explanation = fallback_explanation(ts, row["count"])

            c1, c2 = st.columns([1, 5])
            c1.markdown(f"**{ts}**")
            c2.markdown(explanation)
    else:
        for line in valid_lines:
            ts, exp = line.split("-", 1)

            c1, c2 = st.columns([1, 5])
            c1.markdown(f"**{ts.strip()}**")
            c2.markdown(exp.strip())


# ================================================================
#  LOG TABLE INVESTIGATION
# ==================================================================
import re

st.subheader("🔍 Log Investigation Table")

filtered_df = df_logs.copy()

# ---------- FILTER HEADER ----------
with st.container():
    c1, c2, c3, c4, c5 = st.columns([2, 2, 2, 3, 1])


    with c2:
        platform_filter = st.multiselect(
            "Platform",
            sorted(df_logs["platform"].unique()),
            placeholder="Choose Platform",
            label_visibility="collapsed"
        )

    with c3:
        severity_filter = st.multiselect(
            "Severity",
            sorted(df_logs["severity"].unique()),
            placeholder="Choose Severity",
            label_visibility="collapsed"
        )

    with c4:
        log_search = st.text_input(
            "Search Log",
            placeholder="Paste full or partial log here...",
            label_visibility="collapsed"
        )

    with c5:
        apply_filter = st.button("Apply", use_container_width=True)

# ---------- APPLY FILTERS ----------
if apply_filter:

   

    if platform_filter:
        filtered_df = filtered_df[
            filtered_df["platform"].isin(platform_filter)
        ]

    if severity_filter:
        filtered_df = filtered_df[
            filtered_df["severity"].isin(severity_filter)
        ]

    if log_search:
        search_term = re.escape(log_search.strip())

        filtered_df = filtered_df[
            filtered_df["log"]
            .astype(str)
            .str.replace(r"\s+", " ", regex=True)
            .str.contains(search_term, case=False, regex=True)
        ]

# ---------- DATA TABLE ----------
selected = st.dataframe(
    filtered_df[["timestamp", "platform", "log", "severity", "severity_number"]],
    use_container_width=True,
    height=350,
    selection_mode="single-row",
    on_select="rerun"
)

# ---------------- CLICK → AI ANALYSIS ----------------
if selected and selected["selection"]["rows"]:
    row = filtered_df.iloc[selected["selection"]["rows"][0]]
    log_text = row["log"]
    severity = row["severity"]

    st.divider()
    st.markdown("## 🚨 Selected Log")
    st.code(log_text)

    with st.spinner("🧠 Running AI forensic analysis..."):
        forensic_output = analyze_log(log_text)
        incident = generate_summary_and_mitigation(log_text, severity)

    st.markdown("### 🧠 LLM Forensic Analysis")
    st.code(forensic_output)

    st.markdown("### 🎯 MITRE ATT&CK Mapping")
    mitre = detect_mitre_attack(log_text)
    if mitre:
        for line in format_mitre_for_ui(mitre):
            st.write("•", line)
    else:
        st.success("No MITRE techniques detected.")

    st.markdown("### 📄 Incident Summary")
    st.success(incident.get("summary", ""))

    st.markdown("### 🛡️ Recommended Mitigation")
    for step in incident.get("mitigation", []):
        st.write("•", step)
else:
    st.info("👆 Click a log row to trigger AI investigation")

# ---------------- REAL-TIME CHECKER ----------------
st.subheader("🧪 Real-Time Log Severity Checker")
log_input = st.text_area("Paste any log entry", height=120)

if st.button("🔎 Analyze Log"):
    if log_input.strip():
        severity, sev_num = call_ollama(log_input)
        st.success(f"Severity: {severity} ({sev_num})")

        response = generate_summary_and_mitigation(log_input, severity)
        st.subheader("📄 Incident Summary")
        st.info(response["summary"])

        st.subheader("🛡️ Mitigation")
        for step in response["mitigation"]:
            st.write("•", step)
    else:
        st.warning("Please enter a log.")
