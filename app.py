import streamlit as st
import json
import difflib
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
if 'logged_in' not in st.session_state:
    st.session_state.logged_in = False
if 'username' not in st.session_state:
    st.session_state.username = ""
if 'role' not in st.session_state:
    st.session_state.role = ""
if 'config_history' not in st.session_state:
    st.session_state.config_history = []
if 'activity_log' not in st.session_state:
    st.session_state.activity_log = []

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
            st.rerun()
        else:
            st.sidebar.error("Invalid credentials")

def logout():
    st.session_state.logged_in = False
    st.session_state.username = ""
    st.session_state.role = ""
    st.session_state.activity_log.append(f"{datetime.now()}: User logged out")
    st.rerun()

def parse_config(file):
    try:
        if file.name.endswith('.json'):
            return json.load(file)
        else:
            return {line.split('=')[0].strip(): line.split('=')[1].strip() for line in file.read().decode().split('\n') if '=' in line}
    except:
        return None

def compare_configs(baseline, current):
    differences = []
    for key in set(baseline.keys()) | set(current.keys()):
        baseline_val = baseline.get(key, "N/A")
        current_val = current.get(key, "N/A")
        if baseline_val != current_val:
            change_type = "modified"
            if key not in baseline:
                change_type = "added"
            elif key not in current:
                change_type = "removed"
            differences.append({"key": key, "baseline": baseline_val, "current": current_val, "type": change_type})
    return differences

def calculate_risk_score(differences):
    score = 0
    for diff in differences:
        if diff["type"] == "added" and "user" in diff["key"].lower():
            score += 30
        elif diff["type"] == "removed" and "patch" in diff["key"].lower():
            score += 50
        elif diff["type"] == "modified" and "port" in diff["key"].lower():
            score += 20
    return min(score, 100)

def get_risk_category(score):
    if score >= 70:
        return "High", "red"
    elif score >= 30:
        return "Medium", "orange"
    else:
        return "Low", "green"

if not st.session_state.logged_in:
    login()
else:
    st.sidebar.header(f"Welcome, {st.session_state.username} ({st.session_state.role})")
    if st.sidebar.button("Logout"):
        logout()

    if st.session_state.role == "SysAdmin":
        st.header("Configuration Drift Detector")
        
        col1, col2 = st.columns(2)
        with col1:
            baseline_file = st.file_uploader("Upload Baseline Config", type=["json", "txt"])
        with col2:
            current_file = st.file_uploader("Upload Current Config", type=["json", "txt"])

        if baseline_file and current_file:
            baseline_config = parse_config(baseline_file)
            current_config = parse_config(current_file)
            
            if baseline_config and current_config:
                st.session_state.activity_log.append(f"{datetime.now()}: {st.session_state.username} uploaded configs")
                
                differences = compare_configs(baseline_config, current_config)
                if differences:
                    df = pd.DataFrame(differences)
                    st.subheader("Configuration Differences")
                    st.dataframe(df)

                    change_types = st.multiselect("Filter by Change Type", ["added", "modified", "removed"])
                    if change_types:
                        filtered_df = df[df["type"].isin(change_types)]
                        st.dataframe(filtered_df)
                    else:
                        filtered_df = df

                    risk_score = calculate_risk_score(differences)
                    risk_category, risk_color = get_risk_category(risk_score)
                    st.subheader("Drift Risk Score")
                    st.markdown(f"**Score: {risk_score} ({risk_category})**", unsafe_allow_html=True)
                    st.markdown(f'<span style="color:{risk_color}">{risk_category} Risk</span>', unsafe_allow_html=True)

                    heatmap_data = pd.DataFrame({"System": ["System 1"], "Risk Score": [risk_score]})
                    fig = px.imshow([[risk_score]], text_auto=True, color_continuous_scale="RdYlGn_r", 
                                  labels={"color": "Risk Score"}, height=200)
                    st.subheader("Drift Heatmap")
                    st.plotly_chart(fig, use_container_width=True)

                    st.session_state.config_history.append({
                        "timestamp": datetime.now(),
                        "baseline": baseline_file.name,
                        "current": current_file.name,
                        "differences": differences,
                        "risk_score": risk_score
                    })

                    st.subheader("Historical Comparison")
                    history_df = pd.DataFrame([
                        {"Timestamp": h["timestamp"], "Baseline": h["baseline"], "Current": h["current"], "Risk Score": h["risk_score"]}
                        for h in st.session_state.config_history
                    ])
                    st.dataframe(history_df)

                    time_range = st.slider("Select Time Range (days)", 1, 30, 7)
                    filtered_history = [h for h in st.session_state.config_history 
                                     if (datetime.now() - h["timestamp"]).days <= time_range]
                    if filtered_history:
                        trend_data = pd.DataFrame([
                            {"Timestamp": h["timestamp"], "Risk Score": h["risk_score"]}
                            for h in filtered_history
                        ])
                        fig = px.line(trend_data, x="Timestamp", y="Risk Score", title="Risk Score Trend")
                        st.plotly_chart(fig, use_container_width=True)

        st.subheader("Activity Log")
        st.write(st.session_state.activity_log)
