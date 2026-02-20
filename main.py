from fastapi import FastAPI, UploadFile, File
import shutil
import os
import json
import pickle
import re
import xml.etree.ElementTree as ET
import networkx as nx
import pandas as pd

app = FastAPI()

model = pickle.load(open("models/model.pkl", "rb"))
vectorizer = pickle.load(open("models/vectorizer.pkl", "rb"))
iso = pickle.load(open("models/iso.pkl", "rb"))

def detect_version(file_path):
    if file_path.endswith(".xml"):
        return "1.x"
    else:
        with open(file_path) as f:
            data = json.load(f)
        return data.get("spec_version", "2.0")

def extract_text(file_path, version):
    if version == "1.x":
        tree = ET.parse(file_path)
        root = tree.getroot()
        text = " ".join([elem.text for elem in root.iter() if elem.text])
        return text

    else:
        with open(file_path) as f:
            data = json.load(f)
        texts = []
        for obj in data.get("objects", []):
            texts.append(str(obj.get("name", "")))
            texts.append(str(obj.get("description", "")))
        return " ".join(texts)

def graph_risk(file_path):
    try:
        with open(file_path) as f:
            data = json.load(f)

        G = nx.DiGraph()

        for obj in data.get("objects", []):
            if obj.get("type") != "relationship":
                G.add_node(obj["id"])

        for obj in data.get("objects", []):
            if obj.get("type") == "relationship":
                G.add_edge(obj["source_ref"], obj["target_ref"])

        degree = nx.degree_centrality(G)
        if degree:
            return max(degree.values())
        else:
            return 0
    except:
        return 0

@app.post("/analyze")
async def analyze_file(file: UploadFile = File(...)):

    file_path = f"temp_{file.filename}"

    with open(file_path, "wb") as buffer:
        shutil.copyfileobj(file.file, buffer)

    version = detect_version(file_path)

    text = extract_text(file_path, version)

    vector = vectorizer.transform([text])
    prob = model.predict_proba(vector)[0][1]
    prediction = int(prob > 0.5)

    anomaly_flag = int(iso.predict(vector)[0] == -1)

    credibility = 1 if len(text) > 50 else 0

    graph_score = 0
    if version != "1.x":
        graph_score = graph_risk(file_path)

    final_score = (
        0.5 * prob +
        0.2 * credibility +
        0.2 * graph_score +
        0.1 * anomaly_flag
    )

    if final_score > 0.7:
        risk = "High"
    elif final_score > 0.4:
        risk = "Medium"
    else:
        risk = "Low"

    os.remove(file_path)

    return {
        "detected_version": version,
        "ml_probability": float(prob),
        "prediction": prediction,
        "credibility": credibility,
        "graph_risk": graph_score,
        "anomaly_flag": anomaly_flag,
        "final_risk_score": float(final_score),
        "risk_level": risk
    }