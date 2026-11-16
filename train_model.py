"""
Machine Learning Training Pipeline for Spam & Phishing Detection System
Trains a robust TF-IDF + Classifier model to distinguish:
1. Safe (Legitimate)
2. Spam (Commercial / Unsolicited / Promotions)
3. Phishing (Credential Theft / Urgent Account Impersonation)

Outputs:
- models/spam_model.pkl
- models/tfidf_vectorizer.pkl
- models/model_metrics.json
"""

import json
import os
import sys
import numpy as np
import pandas as pd
import joblib

from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    precision_recall_fscore_support,
    confusion_matrix,
    classification_report
)

# Import local text cleaner
from nlp_engine import clean_text_for_ml


def train():
    base_dir = os.path.dirname(os.path.abspath(__file__))
    dataset_path = os.path.join(base_dir, "dataset", "spam_dataset.csv")
    models_dir = os.path.join(base_dir, "models")
    os.makedirs(models_dir, exist_ok=True)

    print("=" * 65)
    print("AI-BASED SPAM & PHISHING DETECTION: MODEL TRAINING PIPELINE")
    print("=" * 65)

    if not os.path.exists(dataset_path):
        print(f"Error: Dataset not found at {dataset_path}")
        sys.exit(1)

    df = pd.read_csv(dataset_path)
    print(f"Loaded dataset: {len(df)} samples across {df['category'].nunique()} classes.")
    print("Class distribution:")
    for cat, count in df["category"].value_counts().items():
        print(f"  - {cat:10s}: {count:3d} ({count / len(df) * 100:.1f}%)")

    # Combine subject and message text for training
    df["full_text"] = df["subject"].fillna("") + " " + df["message"].fillna("")
    df["cleaned_text"] = df["full_text"].apply(clean_text_for_ml)

    X = df["cleaned_text"]
    y = df["category"]

    # Stratified Train/Test split
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.25, random_state=42, stratify=y
    )

    print(f"\nTraining set: {len(X_train)} samples | Testing set: {len(X_test)} samples")

    # TF-IDF Vectorization with Unigram and Bigram features
    vectorizer = TfidfVectorizer(
        ngram_range=(1, 2),
        max_features=5000,
        sublinear_tf=True,
        min_df=1
    )

    X_train_vec = vectorizer.fit_transform(X_train)
    X_test_vec = vectorizer.transform(X_test)

    # Train Classifier (Logistic Regression with balanced class weights)
    classifier = LogisticRegression(
        C=2.0,
        max_iter=1000,
        class_weight="balanced",
        random_state=42
    )

    classifier.fit(X_train_vec, y_train)

    # Predict on test set
    y_pred = classifier.predict(X_test_vec)
    y_pred_proba = classifier.predict_proba(X_test_vec)

    # Evaluate Metrics
    classes = sorted(list(classifier.classes_))
    acc = float(accuracy_score(y_test, y_pred))
    p_macro, r_macro, f1_macro, _ = precision_recall_fscore_support(y_test, y_pred, average="macro")
    p_weighted, r_weighted, f1_weighted, _ = precision_recall_fscore_support(y_test, y_pred, average="weighted")

    # Per-class metrics
    p_per_class, r_per_class, f1_per_class, support_per_class = precision_recall_fscore_support(
        y_test, y_pred, labels=classes
    )

    per_class_metrics = {}
    for i, c in enumerate(classes):
        per_class_metrics[c] = {
            "precision": round(float(p_per_class[i]), 4),
            "recall": round(float(r_per_class[i]), 4),
            "f1_score": round(float(f1_per_class[i]), 4),
            "support": int(support_per_class[i])
        }

    # Confusion matrix
    cm = confusion_matrix(y_test, y_pred, labels=classes)
    cm_list = cm.tolist()

    # Calculate False Positive Rate (FPR) for legitimate/safe messages flagged as malicious
    # Negative class = 'Safe', Positive classes = 'Spam' or 'Phishing'
    safe_idx = classes.index("Safe") if "Safe" in classes else 0
    safe_true_total = int(sum(cm[safe_idx]))
    safe_correct = int(cm[safe_idx][safe_idx])
    safe_false_positives = safe_true_total - safe_correct
    fpr = round(float(safe_false_positives / max(safe_true_total, 1)), 4)

    # Top indicative keywords per class
    feature_names = np.array(vectorizer.get_feature_names_out())
    top_keywords = {}
    for i, label in enumerate(classes):
        top_indices = np.argsort(classifier.coef_[i])[-10:][::-1]
        top_keywords[label] = feature_names[top_indices].tolist()

    metrics = {
        "model_type": "TF-IDF + Multinomial Logistic Regression",
        "vocabulary_size": len(vectorizer.vocabulary_),
        "classes": classes,
        "sample_count": len(df),
        "test_size": len(y_test),
        "accuracy": round(acc, 4),
        "precision_macro": round(float(p_macro), 4),
        "recall_macro": round(float(r_macro), 4),
        "f1_macro": round(float(f1_macro), 4),
        "precision_weighted": round(float(p_weighted), 4),
        "recall_weighted": round(float(r_weighted), 4),
        "f1_weighted": round(float(f1_weighted), 4),
        "false_positive_rate": fpr,
        "confusion_matrix": cm_list,
        "per_class": per_class_metrics,
        "top_keywords": top_keywords
    }

    # Save artifacts
    model_file = os.path.join(models_dir, "spam_model.pkl")
    vectorizer_file = os.path.join(models_dir, "tfidf_vectorizer.pkl")
    metrics_file = os.path.join(models_dir, "model_metrics.json")

    joblib.dump(classifier, model_file)
    joblib.dump(vectorizer, vectorizer_file)

    with open(metrics_file, "w", encoding="utf-8") as f:
        json.dump(metrics, f, indent=4)

    print("\n" + "=" * 65)
    print("MODEL EVALUATION RESULTS")
    print("=" * 65)
    print(f"Overall Accuracy:       {acc * 100:.2f}%")
    print(f"Macro F1-Score:         {f1_macro * 100:.2f}%")
    print(f"Weighted Precision:     {p_weighted * 100:.2f}%")
    print(f"Weighted Recall:        {r_weighted * 100:.2f}%")
    print(f"False Positive Rate:    {fpr * 100:.2f}%\n")

    print("Detailed Classification Report:")
    print(classification_report(y_test, y_pred, labels=classes))

    print("Confusion Matrix (Rows: True, Cols: Predicted):")
    print(f"        {'  '.join([f'{c[:6]:>6}' for c in classes])}")
    for idx, row in enumerate(cm):
        print(f"{classes[idx][:6]:>6}: {'  '.join([f'{val:>6}' for val in row])}")

    print("\nTop Predictive Features per Class:")
    for label, words in top_keywords.items():
        print(f"  [{label}]: {', '.join(words[:6])}")

    print(f"\nSaved model: {model_file}")
    print(f"Saved vectorizer: {vectorizer_file}")
    print(f"Saved metrics report: {metrics_file}")
    print("=" * 65)

    return metrics


if __name__ == "__main__":
    train()
