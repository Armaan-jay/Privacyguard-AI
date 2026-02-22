"""
Retrain malicious_url_model.pkl from dataset.csv using sklearn.
Run: python ml/retrain_model.py
"""
import pandas as pd
import numpy as np
import pickle
import json
import os
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score

base_dir = os.path.dirname(__file__)
dataset_path = os.path.join(base_dir, 'dataset.csv')
model_path = os.path.join(base_dir, 'malicious_url_model.pkl')
columns_path = os.path.join(base_dir, 'model_columns.json')

print("Loading dataset...")
df = pd.read_csv(dataset_path)
print(f"Dataset shape: {df.shape}")

# Identify the label column
label_col = None
for candidate in ['CLASS', 'class', 'Label', 'label', 'malware', 'target', 'y']:
    if candidate in df.columns:
        label_col = candidate
        break

if not label_col:
    raise ValueError(f"Could not find label column. Available: {df.columns.tolist()[-10:]}")

print(f"Label column: {label_col}")
print(f"Label distribution:\n{df[label_col].value_counts()}")

# Features = all columns except label and ID-like columns
drop_cols = [label_col]
# Drop non-feature columns (id, hash, name, etc.)
for col in df.columns:
    if col.lower() in ('id', 'sha256', 'hash', 'app', 'name', 'package') or 'unnamed' in col.lower():
        drop_cols.append(col)

feature_cols = [c for c in df.columns if c not in drop_cols]
print(f"Feature columns: {len(feature_cols)}")

X = df[feature_cols].fillna(0)
y = df[label_col]

# Train/test split
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)

print(f"\nTraining RandomForest on {len(X_train)} samples...")
clf = RandomForestClassifier(
    n_estimators=150,
    max_depth=20,
    min_samples_split=5,
    random_state=42,
    n_jobs=-1,
    class_weight='balanced'
)
clf.fit(X_train, y_train)

# Evaluate
y_pred = clf.predict(X_test)
acc = accuracy_score(y_test, y_pred)
print(f"\nAccuracy: {acc:.4f}")
print(classification_report(y_test, y_pred))

# Save model
print(f"\nSaving model to {model_path}...")
with open(model_path, 'wb') as f:
    pickle.dump(clf, f)

# Save feature columns
meta = {
    "_schema_version": "3.0",
    "_model_type": "sklearn-RandomForestClassifier",
    "_accuracy": round(float(acc), 4),
    "_label_column": label_col,
    "_label_mapping": {
        "1": "High Risk (Malware)",
        "0": "Low Risk (Benign)"
    },
    "_feature_columns": feature_cols
}
with open(columns_path, 'w') as f:
    json.dump(meta, f, indent=2)

print(f"Done! Model saved to {model_path}")
print(f"Columns metadata saved to {columns_path}")
