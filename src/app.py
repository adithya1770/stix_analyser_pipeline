from fastapi import FastAPI, UploadFile, File
import pickle

from src.parsers import parse_stix
from src.transform import build_dataframe
from src.credibility import apply_credibility
from src.model import predict

app = FastAPI()

model = pickle.load(open("model.pkl", "rb"))
vectorizer = pickle.load(open("vectorizer.pkl", "rb"))

@app.post("/analyze")
async def analyze(file: UploadFile = File(...)):
    raw = await file.read()
    cti = parse_stix(raw)
    df = build_dataframe(cti)
    df = apply_credibility(df)
    text = df["ml_text"].iloc[0]
    result = predict(model, vectorizer, text)
    return {
        "prediction": result,
        "credibility": int(df["Credibility_Score"].iloc[0]),
        "threat_label": int(df["Threat_Label"].iloc[0])
    }
