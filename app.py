import streamlit as st
import json
import pandas as pd
import plotly.express as px
import bcrypt
from datetime import datetime

st.set_page_config(layout="wide")

if 'users' not in st.session_state:
    st.session_state.users = {
        "admin": {"password": bcrypt.hashpw("admin123".encode(), bcrypt.gensalt()).decode(), "role": "SysAdmin"},
        "analyst": {"password": bcrypt.hashpw("analyst123".encode(), bcrypt.gensalt()).decode(), "role": "SecurityAnalyst"}
    }
if 'logged_in' not in st.session_state: st.session_state.logged_in = False
if 'username' not in st.session_state: st.session_state.username = ""
if 'role' not in st.session_state: st.session_state.role = ""
if 'config_history' not in st.session_state: st.session_state.config_history = []
if 'activity_log' not in st.session_state: st.session_state.activity_log = []

def login():
    st.sidebar.header("Login")
    username = st.sidebar.text_input("Username")
    password = st.sidebar.text_input("Password", type="password")
    if st.sidebar.button("Login"):
        if username in st.session_state.users and bcrypt.checkpw(password.encode(), st.session_state.users[username]["password"].encode()):
            st.session_state.logged_in = True
            st.session_state.username = username
            st.session_state.role = st.session_state.users[username]["role"]
            st.session_state.activity_log.append(f"{datetime.now()}: {username} logged in")
            st.experimental_rerun()
        else:
            st.sidebar.error("Invalid credentials")

def logout():
    st.session_state.logged_in = False
    st.session_state.username = ""
    st.session_state.role = ""
    st.session_state.activity_log.append(f"{datetime.now()}: User logged out")
    st.experimental_rerun()

def parse_config(file):
    try:
        if file.name.endswith('.json'):
            return json.load(file)
        return {line.split('=')[0].strip(): line.split('=')[1].strip() for line in file.read().decode().splitlines() if '=' in line}
    except:
        return {}

def compare_configs(base, curr):
    diffs = []
    for key in set(base.keys()) | set(curr.keys()):
        b_val, c_val = base.get(key, "N/A"), curr.get(key, "N/A")
        if b_val != c_val:
            change = "modified"
            if key not in base: change = "added"
            elif key not in curr: change = "removed"
            diffs.append({"key": key, "baseline": b_val, "current": c_val, "type": change})
    return diffs

def calculate_risk(diffs):
    score = sum(30 if d["type"]=="added" and "user" in d["key"].lower() else 50 if d["type"]=="removed" and "patch" in d["key"].lower() else 20 if d["type"]=="modified" and "port" in d["key"].lower() else 0 for d in diffs)
    return min(score, 100)

def risk_category(score):
    if score >= 70: return "High", "red"
    if score >= 30: return "Medium", "orange"
    return "Low", "green"

if not st.session_state.logged_in:
    login()
else:
    st.sidebar.header(f"Welcome, {st.session_state.username} ({st.session_state.role})")
    if st.sidebar.button("Logout"): logout()
    if st.session_state.role == "SysAdmin":
        st.header("Configuration Drift Detector")
        col1, col2 = st.columns(2)
        with col1: baseline_file = st.file_uploader("Upload Baseline Config", type=["json","txt"])
        with col2: current_file = st.file_uploader("Upload Current Config", type=["json","txt"])
        if baseline_file and current_file:
            base_config = parse_config(baseline_file)
            curr_config = parse_config(current_file)
            if base_config and curr_config:
                st.session_state.activity_log.append(f"{datetime.now()}: {st.session_state.username} uploaded configs")
                diffs = compare_configs(base_config, curr_config)
                if diffs:
                    df = pd.DataFrame(diffs)
                    st.subheader("Configuration Differences")
                    st.dataframe(df)
                    types = st.multiselect("Filter by Change Type", ["added","modified","removed"])
                    filtered_df = df[df["type"].isin(types)] if types else df
                    st.dataframe(filtered_df)
                    score = calculate_risk(diffs)
                    category, color = risk_category(score)
                    st.subheader("Drift Risk Score")
                    st.markdown(f"**Score: {score} ({category})**", unsafe_allow_html=True)
                    st.markdown(f'<span style="color:{color}">{category} Risk</span>', unsafe_allow_html=True)
                    fig = px.imshow([[score]], text_auto=True, color_continuous_scale="RdYlGn_r", labels={"color":"Risk Score"}, height=200)
                    st.subheader("Drift Heatmap")
                    st.plotly_chart(fig, use_container_width=True)
                    st.session_state.config_history.append({"timestamp":datetime.now(),"baseline":baseline_file.name,"current":current_file.name,"differences":diffs,"risk_score":score})
                    st.subheader("Historical Comparison")
                    history_df = pd.DataFrame([{"Timestamp":h["timestamp"],"Baseline":h["baseline"],"Current":h["current"],"Risk Score":h["risk_score"]} for h in st.session_state.config_history])
                    st.dataframe(history_df)
                    days = st.slider("Select Time Range (days)", 1, 30, 7)
                    filtered_history = [h for h in st.session_state.config_history if (datetime.now()-h["timestamp"]).days<=days]
                    if filtered_history:
                        trend_df = pd.DataFrame([{"Timestamp":h["timestamp"],"Risk Score":h["risk_score"]} for h in filtered_history])
                        fig = px.line(trend_df, x="Timestamp", y="Risk Score", title="Risk Score Trend")
                        st.plotly_chart(fig, use_container_width=True)
        st.subheader("Activity Log")
        st.write(st.session_state.activity_log)
