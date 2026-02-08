from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.model_selection import train_test_split
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score
import pickle

def train_model(df):

    df["ml_text"] = (
        df["indicator_type"].astype(str) + " " +
        df["description"].astype(str) + " " +
        df["values"].astype(str)
    )

    vectorizer = TfidfVectorizer(lowercase=True, stop_words="english")

    X = vectorizer.fit_transform(df["ml_text"])
    y = df["Threat_Label"]

    train_x, test_x, train_y, test_y = train_test_split(
        X, y, test_size=0.2, random_state=42
    )

    model = LogisticRegression(max_iter=1000)
    model.fit(train_x, train_y)

    prediction = model.predict(test_x)

    print("Accuracy:", accuracy_score(test_y, prediction))

    return model, vectorizer

def predict(model, vectorizer, text):

    sample_vec = vectorizer.transform([text])

    result = model.predict(sample_vec)[0]

    if result == 1:
        return "THREAT"
    else:
        return "BENIGN"

def save_model(model, vectorizer):

    pickle.dump(model, open("model.pkl", "wb"))
    pickle.dump(vectorizer, open("vectorizer.pkl", "wb"))
