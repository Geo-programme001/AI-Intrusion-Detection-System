
import streamlit as st
import pandas as pd
import plotly.express as px
from pathlib import Path
import joblib
from datetime import datetime

# Locate the project root relative to dashboard/app.py.
PROJECT_ROOT = Path(__file__).resolve().parent.parent
MODELS_DIR = PROJECT_ROOT / "models"

MODEL_PATH = MODELS_DIR / "intrusion_detection_model.joblib"
PREPROCESSOR_PATH = MODELS_DIR / "preprocessor.joblib"

# --------------------------------------------------
# LOAD TRAINED MODEL AND PREPROCESSOR
# --------------------------------------------------
model = None
preprocessor = None
model_load_error = None

try:
    if not MODEL_PATH.is_file():
        raise FileNotFoundError(f"Model file not found: {MODEL_PATH}")

    if not PREPROCESSOR_PATH.is_file():
        raise FileNotFoundError(
            f"Preprocessor file not found: {PREPROCESSOR_PATH}"
        )

    model = joblib.load(MODEL_PATH)
    preprocessor = joblib.load(PREPROCESSOR_PATH)

except Exception as exc:
    model_load_error = str(exc)

# --------------------------------------------------
# NSL-KDD FEATURE COLUMNS
# --------------------------------------------------
NSL_KDD_FEATURES = [
    "duration", "protocol_type", "service", "flag", "src_bytes",
    "dst_bytes", "land", "wrong_fragment", "urgent", "hot",
    "num_failed_logins", "logged_in", "num_compromised",
    "root_shell", "su_attempted", "num_root", "num_file_creations",
    "num_shells", "num_access_files", "num_outbound_cmds",
    "is_host_login", "is_guest_login", "count", "srv_count",
    "serror_rate", "srv_serror_rate", "rerror_rate", "srv_rerror_rate",
    "same_srv_rate", "diff_srv_rate", "srv_diff_host_rate",
    "dst_host_count", "dst_host_srv_count", "dst_host_same_srv_rate",
    "dst_host_diff_srv_rate", "dst_host_same_src_port_rate",
    "dst_host_srv_diff_host_rate", "dst_host_serror_rate",
    "dst_host_srv_serror_rate", "dst_host_rerror_rate",
    "dst_host_srv_rerror_rate"
]
# --------------------------------------------------
# PAGE CONFIGURATION
# --------------------------------------------------
st.set_page_config(
    page_title="AI-IDS | Security Operations",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# --------------------------------------------------
# DEMO DATA — NOT REAL DETECTIONS
# --------------------------------------------------
demo_alerts = pd.DataFrame([
    {
        "Time": "14:32:08",
        "Source IP": "192.168.1.15",
        "Destination IP": "192.168.1.10",
        "Classification": "Attack",
        "Severity": "High",
    },
    {
        "Time": "14:31:42",
        "Source IP": "192.168.1.22",
        "Destination IP": "192.168.1.10",
        "Classification": "Normal",
        "Severity": "Info",
    },
    {
        "Time": "14:30:19",
        "Source IP": "10.0.0.8",
        "Destination IP": "192.168.1.20",
        "Classification": "Attack",
        "Severity": "Medium",
    },
    {
        "Time": "14:29:55",
        "Source IP": "192.168.1.30",
        "Destination IP": "192.168.1.10",
        "Classification": "Normal",
        "Severity": "Info",
    },
])

# --------------------------------------------------
# MODEL PREDICTION WORKSPACE
# --------------------------------------------------
st.title("AI-IDS Model Testing")
st.caption("Upload network records to generate model predictions.")

if model is None or preprocessor is None:
    st.error("The trained model or preprocessor could not be loaded.")
else:
    uploaded_file = st.file_uploader(
        "Upload a CSV containing NSL-KDD network records",
        type=["csv"],
        help=(
            "The CSV must contain the 41 NSL-KDD network features "
            "used during model training."
        ),
        key="nsl_kdd_csv_upload",
    )

    if uploaded_file is not None:
        try:
            uploaded_data = pd.read_csv(uploaded_file)

            missing_features = [
                column for column in NSL_KDD_FEATURES
                if column not in uploaded_data.columns
            ]

            if missing_features:
                st.error(
                    "The CSV is missing required features: "
                    + ", ".join(missing_features)
                )
            elif uploaded_data.empty:
                st.warning("The uploaded CSV contains no records.")
            else:
                # Keep only the 41 model input features, in training order.
                model_input = uploaded_data[NSL_KDD_FEATURES].copy()

                # Transform using the preprocessor fitted during training.
                transformed_input = preprocessor.transform(model_input)

                # Generate binary predictions.
                predictions = model.predict(transformed_input)

                results = uploaded_data.copy()
                results["Prediction"] = [
                    "Attack" if prediction == 1 else "Normal"
                    for prediction in predictions
                ]

                st.success(
                    f"Successfully classified {len(results):,} records."
                )

                total_attacks = int((predictions == 1).sum())
                total_normal = int((predictions == 0).sum())

                col1, col2, col3 = st.columns(3)
                col1.metric("Records analyzed", f"{len(results):,}")
                col2.metric("Predicted attacks", f"{total_attacks:,}")
                col3.metric("Predicted normal", f"{total_normal:,}")

                st.subheader("Prediction Results")
                st.dataframe(
                    results,
                    use_container_width=True,
                    hide_index=True,
                )

                csv_output = results.to_csv(index=False).encode("utf-8")

                st.download_button(
                    "Download prediction results",
                    data=csv_output,
                    file_name="ai_ids_predictions.csv",
                    mime="text/csv",
                )

        except Exception as exc:
            st.error(f"Could not process this CSV: {exc}")

# --------------------------------------------------
# SIDEBAR
# --------------------------------------------------
with st.sidebar:
    st.title("🛡️ AI-IDS")
    st.caption("Network Threat Intelligence")
    st.divider()

    page = st.radio(
        "NAVIGATION",
        [
            "Overview",
            "Detection Alerts",
            "Traffic Analysis",
            "Model Information",
        ],
    )


st.divider()
st.caption("SYSTEM STATUS")
st.success("Dashboard online")

if model is not None and preprocessor is not None:
    st.success("Trained model loaded")
    st.info("CSV prediction mode — no live traffic")
else:
    st.error("Trained model unavailable")
    st.warning("Demo data — model not connected")

    if model_load_error:
        st.caption(f"Loading details: {model_load_error}")

# --------------------------------------------------
# OVERVIEW PAGE
# --------------------------------------------------
if page == "Overview":
    st.title("Security Overview")
    st.caption(
        "AI-powered network intrusion monitoring | "
        "Demonstration interface"
    )

    st.info(
        "These figures and records are illustrative demo data, "
        "not live traffic or actual model predictions."
    )

    # Metric cards
    col1, col2, col3, col4 = st.columns(4)

    col1.metric("Flows Analyzed", "1,284", "+84")
    col2.metric("Attacks Detected", "37", "+5")
    col3.metric("Normal Traffic", "1,247", "+79")
    col4.metric("Attack Share", "2.88%", "+0.2%")

    st.divider()

    # Charts
    left, right = st.columns(2)

    with left:
        st.subheader("Traffic Classification")

        classification_data = pd.DataFrame({
            "Classification": ["Normal", "Attack"],
            "Count": [1247, 37],
        })

        fig = px.pie(
            classification_data,
            names="Classification",
            values="Count",
            hole=0.65,
        )

        fig.update_layout(
            margin=dict(t=20, b=20, l=10, r=10),
            legend_title_text="Traffic type",
        )

        st.plotly_chart(fig, use_container_width=True)

    with right:
        st.subheader("Traffic Activity")

        activity_data = pd.DataFrame({
            "Time": ["14:00", "14:05", "14:10", "14:15",
                     "14:20", "14:25", "14:30"],
            "Normal": [90, 110, 105, 130, 120, 145, 150],
            "Attack": [3, 5, 2, 8, 4, 7, 6],
        })

        fig = px.line(
            activity_data,
            x="Time",
            y=["Normal", "Attack"],
            markers=True,
        )

        fig.update_layout(
            margin=dict(t=20, b=20, l=10, r=10),
            xaxis_title="Time",
            yaxis_title="Illustrative flow count",
        )

        st.plotly_chart(fig, use_container_width=True)

    st.divider()
    st.subheader("Recent Detection Records")
    st.dataframe(demo_alerts, use_container_width=True, hide_index=True)

# --------------------------------------------------
# DETECTION ALERTS PAGE
# --------------------------------------------------
elif page == "Detection Alerts":
    st.title("Detection Alerts")
    st.caption("Illustrative records for interface development")

    classification_filter = st.selectbox(
        "Filter by classification",
        ["All", "Attack", "Normal"],
    )

    if classification_filter == "All":
        filtered_alerts = demo_alerts
    else:
        filtered_alerts = demo_alerts[
            demo_alerts["Classification"] == classification_filter
        ]

    st.dataframe(
        filtered_alerts,
        use_container_width=True,
        hide_index=True,
    )

# --------------------------------------------------
# TRAFFIC ANALYSIS PAGE
# --------------------------------------------------
elif page == "Traffic Analysis":
    st.title("Traffic Analysis")
    st.caption("Illustrative traffic statistics")

    st.bar_chart(
        pd.DataFrame({
            "Connections": [120, 145, 132, 170, 160, 185],
        }, index=["14:00", "14:05", "14:10", "14:15", "14:20", "14:25"])
    )

    st.warning("Replace demo values with real flow data when integrated.")

# --------------------------------------------------
# MODEL INFORMATION PAGE
# --------------------------------------------------
elif page == "Model Information":
    st.title("Model Information")

    st.write("**Dataset:** NSL-KDD")
    st.write("**Baseline algorithm:** Random Forest")
    st.write("**Task:** Binary classification")
    st.write("**Class 0:** Normal traffic")
    st.write("**Class 1:** Attack traffic")
    st.write("**Integration status:** Not connected")

    st.info(
        "The trained model will be connected after we verify "
        "the saved model and preprocessing artifacts."
    )
