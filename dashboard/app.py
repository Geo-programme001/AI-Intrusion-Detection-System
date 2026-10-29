
import streamlit as st
import pandas as pd
import plotly.express as px
import joblib
from datetime import datetime
from pathlib import Path
BASE_DIR = Path(__file__).resolve().parent.parent

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
# MODEL PREDICTION WORKSPACE
# --------------------------------------------------
# Store the latest prediction results across Streamlit reruns.
if "prediction_results" not in st.session_state:
    st.session_state["prediction_results"] = None

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
                st.session_state["prediction_results"] = results

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

   # Metrics based on actual predictions when available
    
    prediction_results = st.session_state.get("prediction_results")

    if prediction_results is not None:
        total_records = len(prediction_results)
        total_attacks = int(
            (prediction_results["Prediction"] == "Attack").sum()
        )
        total_normal = int(
            (prediction_results["Prediction"] == "Normal").sum()
        )
        attack_share = (
            total_attacks / total_records * 100
            if total_records > 0 else 0
        )

        col1, col2, col3, col4 = st.columns(4)

        col1.metric("Flows Analyzed", f"{total_records:,}")
        col2.metric("Attacks Detected", f"{total_attacks:,}")
        col3.metric("Normal Traffic", f"{total_normal:,}")
        col4.metric("Attack Share", f"{attack_share:.2f}%")

    else:
        st.info(
            "Upload a CSV in the Model Testing section to see actual "
            "prediction metrics here."
        )
    st.divider()

    # Charts
    
    # Charts
    left, right = st.columns(2)

    with left:
        st.subheader("Traffic Classification")

        if prediction_results is not None:
            classification_data = pd.DataFrame({
                "Classification": ["Normal", "Attack"],
                "Count": [total_normal, total_attacks],
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
        else:
            st.info("Upload a CSV to display prediction classifications.")



    with right:
        st.subheader("Traffic Activity")

        if prediction_results is not None:
            activity_data = pd.DataFrame({
                "Classification": ["Normal", "Attack"],
                "Count": [total_normal, total_attacks],
            })

            fig = px.bar(
                activity_data,
                x="Classification",
                y="Count",
                color="Classification",
                title="Predicted classifications in uploaded CSV",
            )

            fig.update_layout(
                margin=dict(t=40, b=20, l=10, r=10),
                xaxis_title="Classification",
                yaxis_title="Number of records",
                showlegend=False,
            )

            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("Upload a CSV to display traffic activity.")

    st.divider()
    st.subheader("Recent Detection Records")

    if prediction_results is not None:
        st.dataframe(
            prediction_results.tail(10),
            use_container_width=True,
            hide_index=True,
        )
    else:
        st.info("Upload a CSV to display prediction records.")

# --------------------------------------------------
# DETECTION ALERTS PAGE
# --------------------------------------------------
elif page == "Detection Alerts":
    st.title("Detection Alerts")
    prediction_results = st.session_state.get("prediction_results")

    if prediction_results is not None:
        classification_filter = st.selectbox(
            "Filter by classification",
            ["All", "Attack", "Normal"],
        )

        if classification_filter == "All":
            filtered_alerts = prediction_results
        else:
            filtered_alerts = prediction_results[
                prediction_results["Prediction"] == classification_filter
            ]

        st.metric("Matching records", f"{len(filtered_alerts):,}")

        st.dataframe(
            filtered_alerts,
            use_container_width=True,
            hide_index=True,
        )
    else:
        st.info("Upload a CSV in Model Testing to see detection results.")



# --------------------------------------------------
# TRAFFIC ANALYSIS PAGE
# --------------------------------------------------
elif page == "Traffic Analysis":
    st.title("Traffic Analysis")
    st.caption("Analysis of predictions from the uploaded CSV.")

    prediction_results = st.session_state.get("prediction_results")

    if prediction_results is not None:
        traffic_data = (
            prediction_results["Prediction"]
            .value_counts()
            .reindex(["Normal", "Attack"], fill_value=0)
            .rename_axis("Classification")
            .reset_index(name="Count")
        )

        total_records = len(prediction_results)
        traffic_data["Percentage"] = (
            traffic_data["Count"] / total_records * 100
            if total_records > 0 else 0
        )

        col1, col2, col3 = st.columns(3)
        col1.metric("Records analyzed", f"{total_records:,}")
        col2.metric(
            "Predicted attacks",
            f"{int(traffic_data.loc[traffic_data['Classification'] == 'Attack', 'Count'].iloc[0]):,}",
        )
        col3.metric(
            "Predicted normal",
            f"{int(traffic_data.loc[traffic_data['Classification'] == 'Normal', 'Count'].iloc[0]):,}",
        )

        st.subheader("Classification Distribution")

        fig = px.bar(
            traffic_data,
            x="Classification",
            y="Count",
            color="Classification",
            title="Predicted normal vs. attack records",
        )
        fig.update_layout(
            xaxis_title="Predicted class",
            yaxis_title="Number of records",
            showlegend=False,
        )
        st.plotly_chart(fig, use_container_width=True)

        st.subheader("Prediction Summary")
        st.dataframe(
            traffic_data,
            use_container_width=True,
            hide_index=True,
        )
    else:
        st.info("Upload a CSV in Model Testing to view traffic analysis.")



# --------------------------------------------------
# MODEL INFORMATION PAGE
# --------------------------------------------------
elif page == "Model Information":
    st.title("Model Information")
    st.caption(
        "Details about the trained machine-learning model "
        "used to classify network records."
    )

    model_path = BASE_DIR / "models" / "intrusion_detection_model.joblib"
    preprocessor_path = BASE_DIR / "models" / "preprocessor.joblib"

    model_exists = model_path.exists()
    preprocessor_exists = preprocessor_path.exists()

    # Model status
    col1, col2 = st.columns(2)

    with col1:
        st.metric(
            "Trained Model",
            "Available" if model_exists else "Missing",
        )

    with col2:
        st.metric(
            "Preprocessor",
            "Available" if preprocessor_exists else "Missing",
        )

    st.divider()

    # Model details
    st.subheader("Model Details")

    st.write("**Algorithm:** Class-weighted Random Forest")
    st.write("**Dataset:** NSL-KDD")
    st.write("**Input features:** 41 network traffic features")
    st.write("**Task:** Binary classification — Normal or Attack")
    st.write("**Prediction mode:** Uploaded CSV files")

    st.info(
        "This dashboard analyzes records from uploaded datasets. "
        "It does not currently monitor live network traffic."
    )

    st.divider()

    # Evaluation information
    st.subheader("Model Evaluation")

    st.write(
        "The model was evaluated using a held-out NSL-KDD test set. "
        "Its results show that some attacks can be missed."
    )

    st.warning(
        "Do not treat this model as a production-ready security system. "
        "Review its evaluation metrics and false negatives before relying "
        "on its predictions."
    )

    st.caption(
        "Model files are stored in the project's models/ directory."
    )

