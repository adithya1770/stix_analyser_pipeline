from fastapi import FastAPI, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
import os
import pickle
import json
import pandas as pd
import networkx as nx
import numpy as np
from scipy.sparse import hstack
from sklearn.ensemble import IsolationForest
import shap

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

model      = pickle.load(open(os.path.join(BASE_DIR, "models", "model.pkl"),      "rb"))
vectorizer = pickle.load(open(os.path.join(BASE_DIR, "models", "vectorizer.pkl"), "rb"))
scaler     = pickle.load(open(os.path.join(BASE_DIR, "models", "scaler.pkl"),     "rb"))

try:
    explainer = shap.TreeExplainer(model)
except:
    explainer = None

app = FastAPI()
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])


def build_graph(objects):
    G = nx.DiGraph()

    for o in objects:
        if o.get("type") != "relationship" and o.get("id"):
            G.add_node(o["id"])

    for o in objects:
        if o.get("type") == "relationship":
            src = o.get("source_ref")
            tgt = o.get("target_ref")
            if src and tgt:
                G.add_edge(src, tgt)

    return G


def get_risk(row):
    ml   = float(row["ml_probability"])
    cred = float(row.get("credibility_score", 50)) / 100
    anom = int(row.get("anomaly_flag", 0))

    score = round((0.6 * ml + 0.2 * cred + 0.2 * (1 - anom)) * 100, 2)

    if score >= 85:
        return score, "CRITICAL"
    elif score >= 70:
        return score, "HIGH"
    elif score >= 40:
        return score, "MEDIUM"
    else:
        return score, "LOW"


def get_shap(X, df, top_10):
    if explainer is None or len(df) == 0 or len(top_10) == 0:
        return None

    try:
        top_id  = top_10[0]["id"]
        idx     = df.index[df["id"] == top_id].tolist()

        if not idx:
            return None

        sample      = X[idx[0]].toarray()
        shap_values = explainer.shap_values(sample, check_additivity=False)

        if isinstance(shap_values, list):
            vals = shap_values[1][0] if len(shap_values) > 1 else shap_values[0][0]
        else:
            vals = shap_values[0]

        numeric_cols   = ["confidence", "external_ref_count", "validation_flag", "degree", "pagerank"]
        feature_names  = list(vectorizer.get_feature_names_out()) + numeric_cols
        top_indices    = np.argsort(-np.abs(vals))[:10]

        top_features = []
        for i in top_indices:
            name = feature_names[i] if i < len(feature_names) else "f_" + str(i)
            top_features.append({"feature": name, "shap_value": round(float(vals[i]), 4)})

        return {"selected_id": top_id, "top_features": top_features}

    except:
        return None


@app.get("/")
def home():
    return {"message": "STIX Threat Intelligence API is running"}


@app.post("/analyze")
async def analyze(file: UploadFile = File(...)):
    content = await file.read()
    stix    = json.loads(content)
    objects = stix.get("objects", [])

    G        = build_graph(objects)
    degree   = nx.degree_centrality(G)
    pagerank = nx.pagerank(G) if len(G) > 0 else {}

    rows = []
    for o in objects:
        if o.get("type") == "relationship":
            continue

        obj_id = o.get("id", "")
        rows.append({
            "id":                obj_id,
            "type":              o.get("type", ""),
            "description":       o.get("description", ""),
            "confidence":        o.get("confidence", 50),
            "external_ref_count": len(o.get("external_references", [])),
            "validation_flag":   1 if obj_id else 0,
            "degree":            degree.get(obj_id, 0),
            "pagerank":          pagerank.get(obj_id, 0),
        })

    df = pd.DataFrame(rows)

    if df.empty:
        return {
            "total_objects":    0,
            "results":          [],
            "top_10":           [],
            "risk_distribution": {},
            "graph":            {"nodes": G.number_of_nodes(), "edges": G.number_of_edges(), "density": nx.density(G)},
            "shap_explanation": None
        }

    numeric_cols = ["confidence", "external_ref_count", "validation_flag", "degree", "pagerank"]

    df["ml_text"] = df["type"] + " " + df["description"]
    X_text        = vectorizer.transform(df["ml_text"])
    X_numeric     = scaler.transform(df[numeric_cols])
    X             = hstack([X_text, X_numeric])

    try:
        df["ml_probability"] = model.predict_proba(X)[:, 1]
    except:
        df["ml_probability"] = model.predict(X).astype(float)

    iso              = IsolationForest(contamination=0.05, random_state=42)
    anomaly_preds    = iso.fit_predict(df[numeric_cols])
    df["anomaly_flag"] = [1 if p == -1 else 0 for p in anomaly_preds]

    df["credibility_score"] = 50

    scores, levels = zip(*df.apply(get_risk, axis=1))
    df["final_score"] = scores
    df["risk_level"]  = levels

    total = len(df)
    risk_distribution = {}
    for level in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        count = int((df["risk_level"] == level).sum())
        risk_distribution[level.lower()] = {
            "count":   count,
            "percent": round(100 * count / total, 2)
        }

    top_10 = (
        df.sort_values("final_score", ascending=False)
        .head(10)[["id", "type", "ml_probability", "final_score", "risk_level"]]
        .to_dict(orient="records")
    )

    output_cols = ["id", "type", "description", "confidence", "external_ref_count",
                   "validation_flag", "degree", "pagerank", "ml_probability",
                   "anomaly_flag", "final_score", "risk_level"]

    return {
        "total_objects":        total,
        "graph":                {"nodes": G.number_of_nodes(), "edges": G.number_of_edges(), "density": nx.density(G)},
        "risk_distribution":    risk_distribution,
        "top_10":               top_10,
        "shap_explanation":     get_shap(X, df, top_10),
        "results":              df[output_cols].to_dict(orient="records")
    }