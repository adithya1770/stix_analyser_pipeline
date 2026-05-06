import json
import os
import pickle

import networkx as nx
import numpy as np
import pandas as pd
from scipy.sparse import csr_matrix, hstack
from sklearn.cluster import KMeans
from sklearn.ensemble import IsolationForest
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler

os.makedirs("models", exist_ok=True)

DATA_PATH = "data/stix21/enterprise-attack.json"

THREAT_TYPES = {
    "malware", "attack-pattern", "tool",
    "intrusion-set", "campaign", "threat-actor", "vulnerability",
}

CRITICAL_INFRA_KEYWORDS = {
    "energy", "power", "grid", "water", "nuclear", "financial",
    "hospital", "health", "transport", "telecom", "government",
    "defense", "critical", "infrastructure", "utility", "ics", "scada",
}

NUMERIC_COLS = ["confidence", "external_ref_count", "validation_flag", "degree", "pagerank"]


def iter_stix_objects(path):
    with open(path) as f:
        bundle = json.load(f)
    for obj in bundle.get("objects", []):
        yield {
            "id":                  obj.get("id", ""),
            "type":                obj.get("type", ""),
            "description":         obj.get("description", "") or "",
            "confidence":          obj.get("confidence"),
            "external_references": obj.get("external_references", []),
            "source_ref":          obj.get("source_ref"),
            "target_ref":          obj.get("target_ref"),
        }


raw_objects = list(iter_stix_objects(DATA_PATH))
print(f"Total objects: {len(raw_objects)}")

G = nx.DiGraph()
for obj in raw_objects:
    if obj["type"] != "relationship":
        G.add_node(obj["id"])
for obj in raw_objects:
    if obj["type"] == "relationship":
        src, tgt = obj["source_ref"], obj["target_ref"]
        if src and tgt:
            G.add_edge(src, tgt)

pagerank = nx.pagerank(G)
print(f"Graph: {G.number_of_nodes()} nodes, {G.number_of_edges()} edges, density={nx.density(G):.6f}")

rows = []
for obj in raw_objects:
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

del raw_objects

df = pd.DataFrame(rows)
df["type"] = df["type"].astype("category")
print(f"DataFrame: {df.shape[0]} rows, {df.memory_usage(deep=True).sum() / 1e6:.2f} MB")

df["Threat_Label"] = df["type"].astype(str).apply(lambda t: 1 if t in THREAT_TYPES else 0)
print(df["Threat_Label"].value_counts().to_string())


def compute_credibility(row):
    ext   = min(row["external_ref_count"] / 5.0, 1.0) * 40
    valid = row["validation_flag"] * 20
    deg   = min(row["degree"] / 10.0, 1.0) * 20
    conf  = float(row["confidence"]) * (0.7 if row["confidence_missing"] else 1.0)
    conf  = (conf / 100.0) * 20
    return round(min(ext + valid + deg + conf, 100.0), 2)


df["credibility_score"] = df.apply(compute_credibility, axis=1)

df["ml_text"] = df["type"].astype(str) + " " + df["description"].fillna("")

vectorizer      = TfidfVectorizer(stop_words="english", max_features=5000, dtype=np.float32)
X_text          = vectorizer.fit_transform(df["ml_text"])
scaler          = StandardScaler()
X_numeric_dense = scaler.fit_transform(df[NUMERIC_COLS].values.astype(np.float32))
X_numeric       = csr_matrix(X_numeric_dense)
X               = hstack([X_text, X_numeric]).tocsr()
y               = df["Threat_Label"].values

print(f"Feature matrix: {X.shape}")

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)

model = LogisticRegression(max_iter=1000, class_weight="balanced")
model.fit(X_train, y_train)
print(classification_report(y_test, model.predict(X_test)))

df["ml_probability"] = np.clip(model.predict_proba(X)[:, 1], 0.01, 0.99).astype(np.float32)

iso_forest         = IsolationForest(contamination=0.05, random_state=42)
iso_preds          = iso_forest.fit_predict(df[NUMERIC_COLS].values.astype(np.float32))
df["anomaly_flag"] = np.where(iso_preds == -1, 1, 0).astype(np.int8)
print(f"Anomalies: {df['anomaly_flag'].sum()} / {len(df)}")

kmeans       = KMeans(n_clusters=6, random_state=42, n_init=10)
df["cluster"] = kmeans.fit_predict(X_numeric_dense).astype(np.int8)
print(f"Cluster distribution:\n{df['cluster'].value_counts().sort_index().to_string()}")


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


result_cols       = df.apply(calculate_risk, axis=1, result_type="expand")
df["final_score"] = result_cols[0]
df["risk_level"]  = result_cols[1]

print(df["risk_level"].value_counts().to_string())
print(
    df.sort_values("final_score", ascending=False)
    [["id", "type", "ml_probability", "final_score", "risk_level", "is_critical_infra"]]
    .head(10)
    .to_string(index=False)
)

pickle.dump(model,      open("models/model.pkl",      "wb"))
pickle.dump(vectorizer, open("models/vectorizer.pkl", "wb"))
pickle.dump(scaler,     open("models/scaler.pkl",     "wb"))
pickle.dump(iso_forest, open("models/iso_forest.pkl", "wb"))
pickle.dump(kmeans,     open("models/kmeans.pkl",     "wb"))

print("All models saved. Run:  uvicorn api:app --reload")