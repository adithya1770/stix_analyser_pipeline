import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import requests
import streamlit as st

st.set_page_config(page_title="STIX Analyzer", layout="wide")

API_URL = "http://127.0.0.1:8000/analyze"

RISK_COLORS = {
    "Critical": "#d62728",
    "High":     "#ff7f0e",
    "Medium":   "#f0c419",
    "Low":      "#2ca02c",
}

RISK_LEVEL_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]


def speedometer(value):
    fig = go.Figure(go.Indicator(
        mode  = "gauge+number",
        value = value,
        title = {"text": "High / Critical Objects (%)"},
        gauge = {
            "axis":  {"range": [0, 100]},
            "bar":   {"color": "#d62728"},
            "steps": [
                {"range": [0,  40],  "color": "#2ca02c"},
                {"range": [40, 70],  "color": "#f0c419"},
                {"range": [70, 85],  "color": "#ff7f0e"},
                {"range": [85, 100], "color": "#d62728"},
            ],
        },
    ))
    fig.update_layout(height=300, margin=dict(t=50, b=0))
    return fig


def network_graph(graph_data):
    nodes = graph_data.get("nodes", [])
    edges = graph_data.get("edges", [])

    if not nodes:
        return None

    pos = {n["id"]: (n["x"], n["y"]) for n in nodes}

    edge_x, edge_y = [], []
    for e in edges:
        x0, y0 = pos.get(e["source"], (0, 0))
        x1, y1 = pos.get(e["target"], (0, 0))
        edge_x += [x0, x1, None]
        edge_y += [y0, y1, None]

    edge_trace = go.Scatter(
        x=edge_x, y=edge_y,
        mode="lines",
        line=dict(width=0.5, color="#888"),
        hoverinfo="none",
    )

    color_map = {"CRITICAL": "#d62728", "HIGH": "#ff7f0e", "MEDIUM": "#f0c419", "LOW": "#2ca02c"}

    node_x     = [n["x"] for n in nodes]
    node_y     = [n["y"] for n in nodes]
    node_color = [color_map.get(n["risk_level"], "#aec7e8") for n in nodes]
    node_text  = [f"{n['type']}<br>Score: {n['final_score']}" for n in nodes]

    node_trace = go.Scatter(
        x=node_x, y=node_y,
        mode="markers",
        hoverinfo="text",
        text=node_text,
        marker=dict(size=6, color=node_color, line=dict(width=0.5, color="#fff")),
    )

    fig = go.Figure(
        data=[edge_trace, node_trace],
        layout=go.Layout(
            title="Threat Graph — Top 80 Objects by Risk Score",
            showlegend=False,
            hovermode="closest",
            margin=dict(b=20, l=5, r=5, t=40),
            xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
            yaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
            height=550,
        ),
    )
    return fig


st.title("STIX Threat Intelligence Analyzer")

uploaded_file = st.file_uploader("Upload STIX JSON file", type=["json"])

if not uploaded_file:
    st.info("Waiting for a file upload…")
    st.stop()

with st.spinner("Analyzing…"):
    try:
        response = requests.post(
            API_URL,
            files={"file": (uploaded_file.name, uploaded_file.getvalue(), "application/json")},
            timeout=120,
        )
    except requests.exceptions.ConnectionError:
        st.error("Cannot connect to API. Start it with:  uvicorn api:app --reload")
        st.stop()
    except requests.exceptions.Timeout:
        st.error("API timed out.")
        st.stop()

if response.status_code != 200:
    try:
        detail = response.json().get("detail", response.text)
    except Exception:
        detail = response.text
    st.error(f"API error {response.status_code}: {detail}")
    st.stop()

data = response.json()

total        = data.get("total_objects",        0)
graph        = data.get("graph",                {})
risk         = data.get("risk_distribution",    {})
top_10       = data.get("top_10",               [])
results      = data.get("results",              [])
cluster_data = data.get("cluster_data",         [])
graph_data   = data.get("graph_data",           {})
infra_count  = data.get("critical_infra_count", 0)

st.subheader("Summary")

c1, c2, c3, c4, c5 = st.columns(5)
c1.metric("Total Objects",    total)
c2.metric("Graph Nodes",      graph.get("nodes", 0))
c3.metric("Graph Edges",      graph.get("edges", 0))
c4.metric("Graph Density",    f"{graph.get('density', 0):.6f}")
c5.metric("Critical Infra",   infra_count)

density = graph.get("density", 0)
if density < 0.001:
    st.info("Graph connectivity: Very sparse")
elif density < 0.01:
    st.warning("Graph connectivity: Moderately connected")
else:
    st.error("Graph connectivity: Highly connected threat network")

high_count = (
    risk.get("critical", {}).get("count", 0) +
    risk.get("high",     {}).get("count", 0)
)
high_ratio = round((high_count / total) * 100, 2) if total else 0.0
st.plotly_chart(speedometer(high_ratio), use_container_width=True)

st.subheader("Risk Distribution")

if risk:
    risk_rows = [
        {
            "Risk Level":  level.capitalize(),
            "Count":       info.get("count",   0),
            "Percent (%)": info.get("percent", 0.0),
        }
        for level, info in risk.items()
    ]
    df_risk = pd.DataFrame(risk_rows)

    col_pie, col_bar = st.columns(2)

    with col_pie:
        pie = px.pie(
            df_risk, values="Count", names="Risk Level",
            title="Risk Level Breakdown",
            color="Risk Level",
            color_discrete_map=RISK_COLORS,
        )
        st.plotly_chart(pie, use_container_width=True)

    with col_bar:
        bar = px.bar(
            df_risk, x="Risk Level", y="Count",
            title="Object Counts by Risk Level",
            color="Risk Level",
            color_discrete_map=RISK_COLORS,
        )
        st.plotly_chart(bar, use_container_width=True)

    st.dataframe(df_risk, use_container_width=True, hide_index=True)

st.subheader("Cluster Visualization")

if results:
    df_all = pd.DataFrame(results)

    scatter = px.scatter(
        df_all,
        x="ml_probability",
        y="credibility_score",
        color="cluster",
        symbol="risk_level",
        hover_data=["id", "type", "final_score"],
        title="Threat Intelligence Clusters  (ML Probability vs Credibility)",
        labels={
            "ml_probability":   "ML Threat Probability",
            "credibility_score": "Credibility Score",
            "cluster":           "Cluster",
        },
        color_continuous_scale="Turbo",
    )
    scatter.update_traces(marker=dict(size=5, opacity=0.7))
    st.plotly_chart(scatter, use_container_width=True)

if cluster_data:
    df_clusters = pd.DataFrame(cluster_data)
    df_clusters.columns = ["Cluster ID", "Object Count", "Avg Risk Score", "Dominant Type"]
    st.dataframe(df_clusters, use_container_width=True, hide_index=True)

st.subheader("Graph Exploration")

graph_fig = network_graph(graph_data)
if graph_fig:
    st.plotly_chart(graph_fig, use_container_width=True)
    st.caption("Nodes coloured by risk level. Red = CRITICAL, Orange = HIGH, Yellow = MEDIUM, Green = LOW.")
else:
    st.info("No graph data available.")

st.subheader("Top 10 Highest-Risk Objects")

if top_10:
    df_top = pd.DataFrame(top_10)
    df_top["ml_probability"] = df_top["ml_probability"].round(4)
    st.dataframe(df_top, use_container_width=True, hide_index=True)

st.subheader("All Results")

if results:
    df_all = pd.DataFrame(results)

    col_f1, col_f2 = st.columns(2)
    with col_f1:
        levels = ["ALL"] + RISK_LEVEL_ORDER
        chosen = st.selectbox("Filter by risk level", levels)
    with col_f2:
        show_infra = st.checkbox("Show critical infrastructure only", value=False)

    df_show = df_all.copy()
    if chosen != "ALL":
        df_show = df_show[df_show["risk_level"] == chosen]
    if show_infra:
        df_show = df_show[df_show["is_critical_infra"] == 1]

    for col in ["ml_probability", "credibility_score", "final_score", "pagerank"]:
        if col in df_show.columns:
            df_show[col] = df_show[col].round(4)

    st.dataframe(df_show, use_container_width=True, hide_index=True)

    csv = df_all.to_csv(index=False).encode("utf-8")
    st.download_button(
        label="Download full results as CSV",
        data=csv,
        file_name="stix_risk_results.csv",
        mime="text/csv",
    )