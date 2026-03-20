import logging
import os
import json
import pickle
import xml.etree.ElementTree as ET

import numpy as np
import pandas as pd
import networkx as nx
from scipy.sparse import hstack

from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.middleware.cors import CORSMiddleware

import shap

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

BASE_DIR   = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODELS_DIR = os.path.join(BASE_DIR, "models")

NUMERIC_COLS = ["external_ref_count", "validation_flag", "degree", "pagerank"]

STIX1_NS = {
    "stix":      "http://docs.oasis-open.org/cti/ns/stix/core-1",
    "indicator": "http://docs.oasis-open.org/cti/ns/stix/indicator-1",
    "URIObject": "http://docs.oasis-open.org/cti/ns/cybox/objects/uri-2",
}

STIX1_SCHEMA = {
    "STIX_Package": ["version", "id", "timestamp", "Indicators"],
    "Indicator":    ["id", "timestamp", "Type", "Description", "Observable"],
    "Observable":   ["id", "Object", "Title", "Description"],
    "Object":       ["Properties"],
    "URIObject":    ["Value", "condition", "apply_condition", "type"],
}

model      = None
vectorizer = None
scaler     = None
iso_forest = None
explainer  = None


def load_models():
    global model, vectorizer, scaler, iso_forest, explainer

    required = {
        "model":      "model.pkl",
        "vectorizer": "vectorizer.pkl",
        "scaler":     "scaler.pkl",
        "iso_forest": "iso_forest.pkl",
    }

    loaded = {}
    for key, filename in required.items():
        path = os.path.join(MODELS_DIR, filename)
        if not os.path.exists(path):
            raise RuntimeError(
                f"Required model file missing: {path}\n"
                f"  → For iso_forest.pkl run: python scripts/train_isolation_forest.py"
            )
        with open(path, "rb") as f:
            loaded[key] = pickle.load(f)
        logger.info("Loaded %s from %s", key, path)

    model      = loaded["model"]
    vectorizer = loaded["vectorizer"]
    scaler     = loaded["scaler"]
    iso_forest = loaded["iso_forest"]

    try:
        explainer = shap.TreeExplainer(
            model,
            feature_perturbation="tree_path_dependent"
        )
        logger.info("SHAP TreeExplainer initialised")
    except Exception as e:
        logger.warning("SHAP explainer could not be initialised: %s", e)
        explainer = None


app = FastAPI(title="STIX Threat Intelligence API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
def startup_event():
    load_models()


def strip_ns(tag):
    return tag.split("}")[-1]


def convert_stix1x_to_bundle(content: bytes) -> dict:
    try:
        root = ET.fromstring(content)
    except ET.ParseError as e:
        raise HTTPException(status_code=400, detail=f"Invalid STIX 1.x XML: {e}")

    raw_id = root.get("id") or ""
    top_id = raw_id.split(":")[-1] if ":" in raw_id else raw_id

    valid_tags       = [strip_ns(el.tag) for el in root.iter()]
    valid_attributes = [a for el in root.iter() for a in el.attrib.keys()]

    tags_val = False
    attr_val = False
    for key, attributes in STIX1_SCHEMA.items():
        if key in valid_tags:
            tags_val = True
            for at in attributes:
                attr_val = at in valid_attributes

    stix2_objects = []

    for indicator_elem in root.findall(".//stix:Indicator", STIX1_NS):
        raw_id    = indicator_elem.get("id") or ""
        idn       = raw_id.split(":")[-1] if ":" in raw_id else raw_id
        timestamp = indicator_elem.get("timestamp") or ""

        type_elem  = indicator_elem.find(".//indicator:Type",        STIX1_NS)
        desc_elem  = indicator_elem.find(".//indicator:Description", STIX1_NS)
        value_elem = indicator_elem.find(".//URIObject:Value",       STIX1_NS)

        indicator_type = type_elem.text  if type_elem  is not None else ""
        description    = desc_elem.text  if desc_elem  is not None else ""
        raw_values     = value_elem.text if value_elem is not None else ""
        values_list    = raw_values.split("##comma##") if raw_values else []

        pattern_parts = [f"url:value = '{u}'" for u in values_list]
        pattern       = "[ " + " OR ".join(pattern_parts) + " ]" if pattern_parts else ""

        stix2_objects.append({
            "type":                strip_ns(indicator_elem.tag).lower(),
            "id":                  idn,
            "created":             timestamp,
            "modified":            timestamp,
            "labels":              [indicator_type] if indicator_type else [],
            "description":         description,
            "pattern":             pattern,
            "external_references": [],
            "confidence":          None,
        })

    logger.info("STIX 1.x: converted %d indicators", len(stix2_objects))

    return {
        "type":         "bundle",
        "spec_version": "2.1",
        "id":           top_id,
        "objects":      stix2_objects,
    }


def build_graph(objects: list) -> nx.DiGraph:
    G = nx.DiGraph()

    for o in objects:
        if o.get("type") != "relationship":
            obj_id = o.get("id")
            if obj_id:
                G.add_node(obj_id)

    for o in objects:
        if o.get("type") == "relationship":
            src = o.get("source_ref")
            tgt = o.get("target_ref")
            if src and tgt:
                G.add_edge(src, tgt)

    return G


def validate_stix_bundle(data: dict) -> None:
    if not isinstance(data, dict):
        raise HTTPException(status_code=400, detail="Payload must be a JSON object.")

    if data.get("type") != "bundle":
        raise HTTPException(
            status_code=400,
            detail=f"Expected STIX bundle (type='bundle'), got type='{data.get('type')}'."
        )

    if "objects" not in data or not isinstance(data["objects"], list):
        raise HTTPException(
            status_code=400,
            detail="STIX bundle must contain an 'objects' array."
        )

    if len(data["objects"]) == 0:
        raise HTTPException(
            status_code=400,
            detail="STIX bundle 'objects' array is empty."
        )


def build_dataframe(objects: list, G: nx.DiGraph, pagerank: dict) -> pd.DataFrame:
    rows = []
    for o in objects:
        if o.get("type") == "relationship":
            continue

        obj_id   = o.get("id", "")
        obj_type = o.get("type", "")
        raw_conf = o.get("confidence")

        confidence_missing = raw_conf is None
        confidence         = raw_conf if raw_conf is not None else 50

        valid_id = (
            bool(obj_id)
            and "--" in obj_id
            and obj_id.startswith(obj_type + "--")
        )

        rows.append({
            "id":                 obj_id,
            "type":               obj_type,
            "description":        o.get("description", ""),
            "confidence":         confidence,
            "confidence_missing": int(confidence_missing),
            "external_ref_count": len(o.get("external_references", [])),
            "validation_flag":    int(valid_id),
            "degree":             G.degree[obj_id] if obj_id in G else 0,
            "pagerank":           pagerank.get(obj_id, 0.0),
        })

    return pd.DataFrame(rows)


def compute_credibility(row: pd.Series) -> float:
    conf_score = float(row["confidence"])
    if row["confidence_missing"]:
        conf_score *= 0.7

    ext_score    = min(row["external_ref_count"] / 5.0, 1.0) * 20
    valid_score  = float(row["validation_flag"]) * 10
    degree_score = min(row["degree"] / 10.0, 1.0) * 10

    raw = (conf_score * 0.60) + ext_score + valid_score + degree_score
    return round(min(raw, 100.0), 2)


def calculate_risk(row: pd.Series):
    ml   = float(row["ml_probability"])
    cred = float(row["credibility_score"]) / 100.0
    anom = int(row["anomaly_flag"])

    score = round((0.6 * ml + 0.2 * cred + 0.2 * anom) * 100, 2)

    if score >= 85:
        level = "CRITICAL"
    elif score >= 70:
        level = "HIGH"
    elif score >= 40:
        level = "MEDIUM"
    else:
        level = "LOW"

    return score, level


def shap_analysis(X, df: pd.DataFrame, top_10: list):
    if explainer is None:
        logger.warning("SHAP skipped: explainer is None")
        return None
    if df.empty:
        logger.warning("SHAP skipped: dataframe is empty")
        return None
    if not top_10:
        logger.warning("SHAP skipped: top_10 is empty")
        return None

    results       = []
    feature_names = list(vectorizer.get_feature_names_out()) + NUMERIC_COLS

    for entry in top_10:
        top_id = entry["id"]
        idx    = df.index[df["id"] == top_id].tolist()

        if not idx:
            continue

        try:
            sample      = X[idx[0]].toarray()
            shap_values = explainer.shap_values(sample, check_additivity=False)

            if isinstance(shap_values, list):
                values = shap_values[1] if len(shap_values) > 1 else shap_values[0]
            elif isinstance(shap_values, np.ndarray):
                if shap_values.ndim == 3:
                    values = shap_values[0, :, 1]
                elif shap_values.ndim == 2:
                    values = shap_values[0]
                else:
                    values = shap_values
            else:
                values = shap_values

            values = np.array(values).flatten()

            if np.max(np.abs(values)) > 1e6:
                logger.warning("SHAP overflow for id=%s — skipping", top_id)
                continue

            indices  = np.argsort(np.abs(values))[::-1][:10]
            features = [
                {
                    "feature":    feature_names[i] if i < len(feature_names) else f"f_{i}",
                    "shap_value": round(float(values[i]), 4),
                }
                for i in indices
            ]

            results.append({"id": top_id, "top_features": features})

        except Exception as e:
            logger.warning("SHAP failed for id=%s: %s", top_id, e)

    return results if results else None


@app.get("/")
def home():
    return {"message": "STIX Threat Intelligence API is running"}


@app.post("/analyze")
async def analyze(file: UploadFile = File(...)):
    content = await file.read()

    if content.strip().startswith(b"<"):
        stix = convert_stix1x_to_bundle(content)
    else:
        if file.content_type not in ("application/json", "text/plain", "application/octet-stream"):
            raise HTTPException(
                status_code=400,
                detail=f"Expected a JSON file, received content-type: {file.content_type}",
            )
        try:
            stix = json.loads(content)
        except json.JSONDecodeError as e:
            raise HTTPException(status_code=400, detail=f"Invalid JSON: {e}")

    validate_stix_bundle(stix)

    objects  = stix.get("objects", [])
    G        = build_graph(objects)
    pagerank = nx.pagerank(G) if len(G) > 0 else {}
    df       = build_dataframe(objects, G, pagerank)

    if df.empty:
        return {
            "total_objects":     0,
            "results":           [],
            "top_10":            [],
            "risk_distribution": {},
            "graph": {
                "nodes":   G.number_of_nodes(),
                "edges":   G.number_of_edges(),
                "density": nx.density(G),
            },
            "shap_explanation": None,
        }

    df["ml_text"] = df["type"] + " " + df["description"]
    X_text        = vectorizer.transform(df["ml_text"])
    X_numeric     = scaler.transform(df[NUMERIC_COLS].values)
    X             = hstack([X_text, X_numeric]).tocsr()

    try:
        probs = model.predict_proba(X)[:, 1]
    except AttributeError as e:
        logger.warning("predict_proba unavailable (%s), falling back to predict", e)
        probs = model.predict(X).astype(float)

    df["ml_probability"]    = np.clip(probs, 0.01, 0.99)
    iso_preds               = iso_forest.predict(df[NUMERIC_COLS].values)
    df["anomaly_flag"]      = [1 if p == -1 else 0 for p in iso_preds]
    df["credibility_score"] = df.apply(compute_credibility, axis=1)

    risk_results      = df.apply(calculate_risk, axis=1, result_type="expand")
    df["final_score"] = risk_results[0]
    df["risk_level"]  = risk_results[1]

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
        .head(10)[["id", "type", "ml_probability", "final_score", "risk_level"]]
        .to_dict(orient="records")
    )

    output_cols = [
        "id", "type", "description", "confidence", "confidence_missing",
        "external_ref_count", "validation_flag", "degree", "pagerank",
        "ml_probability", "anomaly_flag", "credibility_score",
        "final_score", "risk_level",
    ]

    return {
        "total_objects": total,
        "graph": {
            "nodes":   G.number_of_nodes(),
            "edges":   G.number_of_edges(),
            "density": nx.density(G),
        },
        "risk_distribution": risk_distribution,
        "top_10":            top_10,
        "shap_explanation":  shap_analysis(X, df, top_10),
        "results":           df[output_cols].to_dict(orient="records"),
    }