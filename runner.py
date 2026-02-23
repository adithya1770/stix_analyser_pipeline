import streamlit as st
import pandas as pd
import requests
import plotly.graph_objects as go
import plotly.express as px

st.set_page_config(page_title="STIX Analyzer", layout="wide")

st.title("STIX Threat Intelligence Analyzer")

API_URL = "http://127.0.0.1:8000/analyze"

uploaded_file = st.file_uploader("Upload STIX JSON file", type=["json"])


def speedometer(value):
    fig = go.Figure(go.Indicator(
        mode="gauge+number",
        value=value,
        title={'text': "Overall Threat Level (%)"},
        gauge={
            'axis': {'range': [0, 100]},
            'bar': {'color': "red"},
            'steps': [
                {'range': [0, 35], 'color': "green"},
                {'range': [35, 55], 'color': "yellow"},
                {'range': [55, 75], 'color': "orange"},
                {'range': [75, 100], 'color': "red"},
            ],
        }
    ))
    fig.update_layout(height=300)
    return fig


if uploaded_file:
    with st.spinner("Analyzing..."):
        files = {"file": (uploaded_file.name, uploaded_file.getvalue(), "application/json")}
        response = requests.post(API_URL, files=files)

    if response.status_code != 200:
        st.error("Error analyzing file.")
    else:
        data = response.json()

        total = data.get("total_objects", 0)
        graph = data.get("graph", {})
        risk = data.get("risk_distribution", {})
        top_10 = data.get("top_10", [])
        results = data.get("results", [])

        nodes = graph.get("nodes", 0)
        edges = graph.get("edges", 0)
        density = graph.get("density", 0)

        st.subheader("Summary Overview")

        col1, col2, col3 = st.columns(3)

        col1.metric("Total Objects", total)
        col2.metric("Graph Nodes", nodes)
        col3.metric("Graph Edges", edges)

        st.metric("Graph Density", round(density, 6))

        if density < 0.001:
            st.info("Graph Connectivity: Very Sparse Network")
        elif density < 0.01:
            st.warning("Graph Connectivity: Moderately Connected")
        else:
            st.error("Graph Connectivity: Highly Connected Threat Network")

        high = risk.get("critical", {}).get("count", 0) + \
               risk.get("high", {}).get("count", 0)

        overall_percent = round((high / total) * 100, 2) if total else 0

        st.plotly_chart(speedometer(overall_percent), use_container_width=True)

        st.subheader("Risk Distribution")

        if risk:
            df_risk = pd.DataFrame(risk).T.reset_index()
            df_risk.columns = ["Risk Level", "Count", "Percent"]

            pie = px.pie(
                df_risk,
                values="Count",
                names="Risk Level",
                title="Risk Level Breakdown",
                color_discrete_sequence=px.colors.sequential.Reds
            )

            st.plotly_chart(pie, use_container_width=True)
            st.dataframe(df_risk)

        st.subheader("Top 10 High Risk Objects")

        if top_10:
            st.dataframe(pd.DataFrame(top_10))

        st.subheader("Detailed Results")

        if results:
            df_results = pd.DataFrame(results)
            st.dataframe(df_results)