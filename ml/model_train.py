
import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score
import pickle
import json
import os

# Set paths
base_dir = os.path.dirname(__file__)
dataset_path = os.path.join(base_dir, 'dataset.csv')
model_path = os.path.join(base_dir, 'risk_model.pkl')
columns_path = os.path.join(base_dir, 'model_columns.json')

# Load and clean data
print("Loading dataset...")
try:
    df = pd.read_csv(dataset_path)
except FileNotFoundError:
    print(f"Error: Dataset not found at {dataset_path}")
    print("Please run 'node ml/download_data.js' first.")
    exit(1)

# Inspect columns to find the target class
# The dataset typically has 'CLASS' as the target (1 = Malware, 0 = Benign)
target_col = 'CLASS' 
if target_col not in df.columns:
    # Fallback search if column name differs
    possible_targets = ['class', 'Class', 'Label', 'label', 'Risk']
    for col in possible_targets:
        if col in df.columns:
            target_col = col
            break

print(f"Target column identified as: {target_col}")

# Drop non-feature columns if any (Name is usually not useful for generalizable permission models)
if 'NAME' in df.columns:
    df = df.drop(columns=['NAME'])

# Separate Features (X) and Target (y)
X = df.drop(columns=[target_col])
y = df[target_col]

# Handle potential missing values
X = X.fillna(0)

# Save feature column names for prediction alignment
feature_columns = list(X.columns)
with open(columns_path, 'w') as f:
    json.dump(feature_columns, f)
print(f"Saved {len(feature_columns)} feature names to {columns_path}")

# Train/Test Split
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# Initialize Random Forest
print("Training Random Forest Classifier...")
rf = RandomForestClassifier(n_estimators=100, random_state=42)
rf.fit(X_train, y_train)

# Evaluate
y_pred = rf.predict(X_test)
print("Model Accuracy:", accuracy_score(y_test, y_pred))
print("\nClassification Report:\n", classification_report(y_test, y_pred))

# Save Model
with open(model_path, 'wb') as f:
    pickle.dump(rf, f)

print(f"Model saved to {model_path}")
