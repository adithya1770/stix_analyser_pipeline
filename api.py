import json
import pickle

import networkx as nx
import numpy as np
import pandas as pd
from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from scipy.sparse import csr_matrix, hstack

model      = pickle.load(open("models/model.pkl",      "rb"))
vectorizer = pickle.load(open("models/vectorizer.pkl", "rb"))
scaler     = pickle.load(open("models/scaler.pkl",     "rb"))
iso_forest = pickle.load(open("models/iso_forest.pkl", "rb"))
kmeans     = pickle.load(open("models/kmeans.pkl",     "rb"))

NUMERIC_COLS = ["confidence", "external_ref_count", "validation_flag", "degree", "pagerank"]

CRITICAL_INFRA_KEYWORDS = {
    "energy", "power", "grid", "water", "nuclear", "financial",
    "hospital", "health", "transport", "telecom", "government",
    "defense", "critical", "infrastructure", "utility", "ics", "scada",
}

app = FastAPI(title="STIX Threat Intelligence API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


def iter_stix_objects(objects):
    for obj in objects:
        yield {
            "id":                  obj.get("id", ""),
            "type":                obj.get("type", ""),
            "description":         obj.get("description", "") or "",
            "confidence":          obj.get("confidence"),
            "external_references": obj.get("external_references", []),
            "source_ref":          obj.get("source_ref"),
            "target_ref":          obj.get("target_ref"),
        }


def build_graph(raw):
    G = nx.DiGraph()
    for obj in raw:
        if obj["type"] != "relationship":
            G.add_node(obj["id"])
    for obj in raw:
        if obj["type"] == "relationship":
            src, tgt = obj["source_ref"], obj["target_ref"]
            if src and tgt:
                G.add_edge(src, tgt)
    pagerank = nx.pagerank(G) if len(G) > 0 else {}
    return G, pagerank


def build_dataframe(raw, G, pagerank):
    rows = []
    for obj in raw:
        if obj["type"] == "relationship":
            continue
        obj_id, obj_type = obj["id"], obj["type"]
        raw_conf           = obj["confidence"]
        confidence         = raw_conf if raw_conf is not None else 50
        confidence_missing = 1 if raw_conf is None else 0
        ext_refs           = len(obj["external_references"])
        valid_id           = 1 if ("--" in obj_id and obj_id.startswith(obj_type + "--")) else 0
        desc_lower         = obj["description"].lower()
        is_critical_infra  = int(
            obj_type == "vulnerability" or
            any(kw in desc_lower for kw in CRITICAL_INFRA_KEYWORDS)
        )
        rows.append({
            "id":                 obj_id,
            "type":               obj_type,
            "description":        obj["description"],
            "confidence":         np.float32(confidence),
            "confidence_missing": np.int8(confidence_missing),
            "external_ref_count": np.int16(ext_refs),
            "validation_flag":    np.int8(valid_id),
            "degree":             np.int16(G.degree[obj_id] if obj_id in G else 0),
            "pagerank":           np.float32(pagerank.get(obj_id, 0.0)),
            "is_critical_infra":  np.int8(is_critical_infra),
        })
    return pd.DataFrame(rows)


def compute_credibility(row):
    ext   = min(row["external_ref_count"] / 5.0, 1.0) * 40
    valid = row["validation_flag"] * 20
    deg   = min(row["degree"] / 10.0, 1.0) * 20
    conf  = float(row["confidence"]) * (0.7 if row["confidence_missing"] else 1.0)
    conf  = (conf / 100.0) * 20
    return round(min(ext + valid + deg + conf, 100.0), 2)


def calculate_risk(row):
    ml    = float(row["ml_probability"])
    cred  = float(row["credibility_score"]) / 100.0
    anom  = int(row["anomaly_flag"])
    infra = int(row["is_critical_infra"])
    score = round((0.5 * ml + 0.2 * cred + 0.2 * anom + 0.1 * infra) * 100, 2)
    level = (
        "CRITICAL" if score >= 85 else
        "HIGH"     if score >= 70 else
        "MEDIUM"   if score >= 40 else
        "LOW"
    )
    return score, level


def build_graph_json(G, df, pagerank, top_n=80):
    top_ids = set(
        df.sort_values("final_score", ascending=False)
        .head(top_n)["id"]
        .tolist()
    )
    sub = G.subgraph(top_ids)
    pos = nx.spring_layout(sub, seed=42)

    id_to_row = df.set_index("id")

    nodes = []
    for node_id in sub.nodes():
        x, y = pos[node_id]
        row  = id_to_row.loc[node_id] if node_id in id_to_row.index else None
        nodes.append({
            "id":          node_id,
            "type":        row["type"] if row is not None else "unknown",
            "risk_level":  row["risk_level"] if row is not None else "LOW",
            "final_score": float(row["final_score"]) if row is not None else 0.0,
            "x":           float(x),
            "y":           float(y),
        })

    edges = [
        {"source": u, "target": v}
        for u, v in sub.edges()
    ]

    return {"nodes": nodes, "edges": edges}


@app.get("/")
def home():
    return {"message": "STIX Threat Intelligence API is running"}


@app.post("/analyze")
async def analyze(file: UploadFile = File(...)):
    content = await file.read()

    try:
        stix = json.loads(content)
    except json.JSONDecodeError:
        raise HTTPException(status_code=400, detail="File is not valid JSON.")

    if stix.get("type") != "bundle":
        raise HTTPException(status_code=400, detail="Expected a STIX bundle (type='bundle').")
    if not isinstance(stix.get("objects"), list) or len(stix["objects"]) == 0:
        raise HTTPException(status_code=400, detail="Bundle must contain a non-empty 'objects' list.")

    raw = list(iter_stix_objects(stix["objects"]))
    G, pagerank = build_graph(raw)
    df = build_dataframe(raw, G, pagerank)

    if df.empty:
        return {
            "total_objects": 0, "results": [], "top_10": [],
            "risk_distribution": {}, "graph_data": {"nodes": [], "edges": []},
            "cluster_data": [], "critical_infra_count": 0,
            "graph": {"nodes": 0, "edges": 0, "density": 0},
        }

    df["ml_text"]   = df["type"].astype(str) + " " + df["description"].fillna("")
    X_text          = vectorizer.transform(df["ml_text"])
    X_numeric_dense = scaler.transform(df[NUMERIC_COLS].values.astype(np.float32))
    X_numeric       = csr_matrix(X_numeric_dense)
    X               = hstack([X_text, X_numeric]).tocsr()

    df["ml_probability"]  = np.clip(model.predict_proba(X)[:, 1], 0.01, 0.99).astype(np.float32)
    iso_preds             = iso_forest.predict(df[NUMERIC_COLS].values.astype(np.float32))
    df["anomaly_flag"]    = np.where(iso_preds == -1, 1, 0).astype(np.int8)
    df["cluster"]         = kmeans.predict(X_numeric_dense).astype(np.int8)
    df["credibility_score"] = df.apply(compute_credibility, axis=1)

    result_cols       = df.apply(calculate_risk, axis=1, result_type="expand")
    df["final_score"] = result_cols[0]
    df["risk_level"]  = result_cols[1]

    total = len(df)

    risk_distribution = {
        level.lower(): {
            "count":   int((df["risk_level"] == level).sum()),
            "percent": round(100 * (df["risk_level"] == level).sum() / total, 2),
        }
        for level in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    }

    top_10 = (
        df.sort_values("final_score", ascending=False)
        .head(10)[["id", "type", "ml_probability", "final_score", "risk_level", "is_critical_infra"]]
        .to_dict(orient="records")
    )

    cluster_data = (
        df.groupby("cluster")
        .agg(
            count=("id", "count"),
            avg_score=("final_score", "mean"),
            dominant_type=("type", lambda x: x.value_counts().index[0]),
        )
        .reset_index()
        .rename(columns={"cluster": "cluster_id"})
        .assign(avg_score=lambda d: d["avg_score"].round(2))
        .to_dict(orient="records")
    )

    output_cols = [
        "id", "type", "description", "confidence", "external_ref_count",
        "validation_flag", "degree", "pagerank", "ml_probability",
        "anomaly_flag", "credibility_score", "final_score", "risk_level",
        "is_critical_infra", "cluster",
    ]

    return {
        "total_objects":        total,
        "critical_infra_count": int(df["is_critical_infra"].sum()),
        "graph": {
            "nodes":   G.number_of_nodes(),
            "edges":   G.number_of_edges(),
            "density": nx.density(G),
        },
        "risk_distribution": risk_distribution,
        "top_10":            top_10,
        "cluster_data":      cluster_data,
        "graph_data":        build_graph_json(G, df, pagerank),
        "results":           df[output_cols].to_dict(orient="records"),
    }