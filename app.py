import streamlit as st
import pandas as pd
import joblib
from datetime import datetime
import plotly.graph_objects as go

# --- Page Config ---
st.set_page_config(
    page_title="NIDS Dashboard",
    layout="wide",
    initial_sidebar_state="expanded"
)

# --- Load Model & Assets ---
@st.cache_resource
def load_assets():
    model = joblib.load("model.pkl")
    label_map = joblib.load("label_map.pkl")
    model_features = joblib.load("model_features.pkl")
    model_features = [f for f in model_features if f != "Label"]
    return model, label_map, model_features

model, label_map, model_features = load_assets()

# --- CSS ---
st.markdown("""
    <style>
    body, .main {
        background-color: #f0f4f8;
        font-family: 'Segoe UI', sans-serif;
    }
    .metric-box {
        background-color: #ffffff;
        border-radius: 14px;
        padding: 25px;
        box-shadow: 0 6px 15px rgba(0,0,0,0.1);
        text-align: center;
        transition: transform 0.2s;
    }
    .metric-box:hover {
        transform: scale(1.03);
    }
    .title {
        font-size: 42px;
        font-weight: bold;
        color: #0f172a;
        text-align: center;
        margin-bottom: 20px;
    }
    .center-text {
        text-align: center;
        font-size: 26px;
        color: #0f172a;
        font-weight: bold;
        margin: 20px 0;
    }
    .dataframe th {
        background-color: #1f2937 !important;
        color: white !important;
    }
    </style>
""", unsafe_allow_html=True)

# --- Sidebar ---
st.sidebar.title("🧭 Navigation")
page = st.sidebar.radio("Go to", ["🏠 Dashboard", "📤 Upload Data", "🧠 Predictions", "📊 Visualization", "ℹ️ About"])

# --- Title ---
# st.markdown('<div class="title">🛡️ Network Intrusion Detection System</div>', unsafe_allow_html=True)

# --- Dashboard Page ---

if page == "🏠 Dashboard":
    st.markdown("""
        <div style='text-align: center;'>
            <h1 style='font-size:42px; color:#0f172a;'>🛡️ Network Intrusion Detection System</h1>
            <h3 style='font-size:24px; color:#334155;'>Leveraging Machine Learning to Secure Networks</h3>
        </div>
    """, unsafe_allow_html=True)

   

    st.markdown("""
        <div style='text-align: center; font-size:18px; color:#475569; margin-top:20px;'>
            🚀 This project analyzes network traffic data using advanced machine learning models 
            to detect potential intrusions and cyber threats in real-time.
        </div>
    """, unsafe_allow_html=True)
    st.markdown("""
        <div style='text-align: center; font-size:22px; color:#475569; margin-top:20px;'>
             Steps to Follow
        </div>
    """, unsafe_allow_html=True)

    # Feature highlights
    col1, col2, col3 = st.columns(3)
    with col1:
        st.markdown("""
            <div class='metric-box'>
                📂<br><h4>Upload Data</h4>
                <p style='color:#475569;'>Upload your network traffic CSV files for analysis.</p>
            </div>
        """, unsafe_allow_html=True)
    with col2:
        st.markdown("""
            <div class='metric-box'>
                🤖<br><h4>Run Predictions</h4>
                <p style='color:#475569;'>Detect attacks using our trained ML model.</p>
            </div>
        """, unsafe_allow_html=True)
    with col3:
        st.markdown("""
            <div class='metric-box'>
                📊<br><h4>Visual Insights</h4>
                <p style='color:#475569;'>Explore interactive charts of detected intrusions.</p>
            </div>
        """, unsafe_allow_html=True)




# --- Upload Data ---
elif page == "📤 Upload Data":
    st.subheader("📤 Upload Your Network Traffic Data (CSV Format)")
    uploaded_file = st.file_uploader("Select your CSV file", type=["csv"])
    if uploaded_file is not None:
        df = pd.read_csv(uploaded_file)
        st.success("✅ File Uploaded Successfully!")
        st.dataframe(df.head(10), use_container_width=True)
        st.session_state["uploaded_data"] = df

# --- Predictions Page ---
elif page == "🧠 Predictions":
    st.subheader("🤖 Intrusion Detection Predictions")
    if "uploaded_data" not in st.session_state:
        st.warning("⚠️ Please upload a CSV file first from the Upload tab.")
    else:
        df = st.session_state["uploaded_data"]
        allowed_features = [
            'sport', 'dur', 'sbytes', 'dbytes', 'sttl', 'dttl', 'sloss', 'dloss',
            'Sload', 'Dload', 'Spkts', 'Dpkts', 'swin', 'dwin', 'stcpb', 'dtcpb',
            'smeansz', 'dmeansz', 'trans_depth', 'Sjit', 'Djit', 'tcprtt', 'synack',
            'ackdat', 'ct_state_ttl', 'ct_srv_src', 'ct_srv_dst', 'ct_dst_ltm',
            'ct_src_ltm', 'ct_src_dport_ltm', 'ct_dst_sport_ltm', 'ct_dst_src_ltm',
            'proto_any', 'proto_gre', 'proto_ospf', 'proto_sctp',
            'proto_tcp', 'proto_udp', 'proto_unas', 'state_CON', 'state_FIN',
            'state_INT', 'service_dns', 'service_ftp', 'service_ftp-data',
            'service_http', 'service_pop3', 'service_smtp', 'service_snmp'
        ]
        input_df = df[[col for col in allowed_features if col in df.columns]].copy()
        for feature in allowed_features:
            if feature not in input_df.columns:
                input_df[feature] = 0
        input_df = input_df[allowed_features]

        predictions = model.predict(input_df)
        attack_names = [label_map.get(int(p), "Unknown") for p in predictions]
        df["Attack Type"] = attack_names

        display_cols = [col for col in ["srcip", "dstip", "proto"] if col in df.columns] + ["Attack Type"]

        st.markdown('<div class="center-text">🔍 Prediction Summary (srcip, dstip, proto & attack type)</div>', unsafe_allow_html=True)
        st.dataframe(df[display_cols].head(20), use_container_width=True)

        st.session_state["predicted_data"] = df
        csv = df.to_csv(index=False).encode('utf-8')
        st.download_button("📥 Download Full Predictions CSV", csv, "predictions.csv", "text/csv")

# --- Visualization Page ---
elif page == "📊 Visualization":
    
    if "predicted_data" not in st.session_state:
        st.warning("⚠️ Please make predictions first.")
    else:
        df = st.session_state["predicted_data"]
        attack_counts = df["Attack Type"].value_counts()

        st.markdown('<div class="center-text">📌 Attack Type Proportion</div>', unsafe_allow_html=True)

        fig = go.Figure(data=[go.Pie(
            labels=attack_counts.index, 
            values=attack_counts.values,
            hole=0.4,
            textinfo='label+percent',
            insidetextorientation='radial',
            marker=dict(colors=['#EF553B', '#00CC96', '#AB63FA', '#FFA15A', '#19D3F3', '#FF6692', '#B6E880', '#FF97FF'])
        )])
        
        fig.update_layout(
            title_text='🛡️ Types of Detected Attacks',
            title_font_size=24,
            margin=dict(t=50, b=30, l=0, r=0),
            legend=dict(font=dict(size=14))
        )
        st.plotly_chart(fig, use_container_width=True)

# --- About Page ---
elif page == "ℹ️ About":
    st.subheader("ℹ️ About This Project")
    st.markdown("""
        <div style='font-size:18px; color:#1f2937;'>
        🚀 This **Network Intrusion Detection System (NIDS)** dashboard enables you to upload network traffic data,
        run ML predictions to detect attacks, and view insightful interactive visualizations.
        <br><br>
        ✅ Built with <strong>Streamlit, pandas, joblib, Plotly</strong>.<br>
        🎨 Enhanced UI for a better analytical experience.
        <br><br>
        <strong>Developed by: Surabhi Pilane 💻</strong>
        </div>
    """, unsafe_allow_html=True)
