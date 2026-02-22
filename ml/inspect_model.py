import pickle, sys

with open('ml/malicious_url_model.pkl', 'rb') as f:
    model = pickle.load(f)

print('=== MODEL TYPE ===')
print(type(model).__name__)

# If sklearn Pipeline
if hasattr(model, 'steps'):
    print('\n=== PIPELINE STEPS ===')
    for name, step in model.steps:
        print(f'  {name}: {type(step).__name__}')
    last = model.steps[-1][1]
else:
    last = model

# Classifier details
print('\n=== CLASSIFIER ===')
print('Type:', type(last).__name__)
if hasattr(last, 'classes_'):
    print('Classes:', last.classes_)
if hasattr(last, 'n_features_in_'):
    print('n_features_in_:', last.n_features_in_)
if hasattr(last, 'feature_importances_'):
    print('Has feature_importances_: Yes')
if hasattr(last, 'feature_names_in_'):
    print('Feature names:', list(last.feature_names_in_)[:30])

# If has a vectorizer step
if hasattr(model, 'steps'):
    first = model.steps[0][1]
    print('\n=== FIRST STEP ===')
    print('Type:', type(first).__name__)
    if hasattr(first, 'vocabulary_'):
        print('Vocabulary size:', len(first.vocabulary_))
        print('Sample (first 15):', list(first.vocabulary_.keys())[:15])

# Try a dummy predict to reveal feature shape
print('\n=== QUICK TEST ===')
try:
    import numpy as np
    # Try text input (pipeline with vectorizer)
    res = model.predict(['http://malicious-site.com/steal?token=abc'])
    print('Text input worked. Output:', res)
except Exception as e:
    print('Text input failed:', e)
    try:
        # Try numeric input
        dummy = [[0.5]*last.n_features_in_]
        res = model.predict(dummy)
        print('Numeric input worked. Output:', res)
    except Exception as e2:
        print('Numeric input also failed:', e2)
