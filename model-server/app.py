# ==============================================================================
# 1. IMPORTS & INITIALIZATION
# ==============================================================================
import joblib
import pandas as pd
import numpy as np
import re
from flask import Flask, request, jsonify
from flask_cors import CORS
import os # Added for environment variable handling

# Initialize the Flask application
app = Flask(__name__)
# Enable CORS for communication with the Node.js backend/React frontend
CORS(app)


# ==============================================================================
# 2. LOAD MODEL ASSETS
# ==============================================================================
# Define paths to the pre-trained model and the label encoder
# Use environment variables or default to the relative path
MODEL_PATH = os.environ.get('MODEL_PATH', './models/final/cyber_threat_model_xgboost.joblib')
ENCODER_PATH = os.environ.get('ENCODER_PATH', './models/final/label_encoder.joblib')

# Load the assets with error handling
try:
    model = joblib.load(MODEL_PATH)
    label_encoder = joblib.load(ENCODER_PATH)
    print(f"✅ Model ({MODEL_PATH}) and label encoder loaded successfully.")
except Exception as e:
    print(f"❌ Error loading model assets from path: {MODEL_PATH}. Details: {e}")
    model = None
    label_encoder = None


# ==============================================================================
# 3. PREPROCESSING FUNCTION
# ==============================================================================
def preprocess_input(df: pd.DataFrame) -> pd.DataFrame:
    """
    Ensures new data is transformed in the exact same way as the training data.
    This is critical for the model to make accurate predictions.
    """
    if df.empty:
        return pd.DataFrame()

    # a. Standardize column names to snake_case (e.g., "Dst Port" -> "dst_port")
    # This regex is robust and correctly handles spaces and special characters.
    new_cols = [re.sub(r'[^a-zA-Z0-9]+', '_', col).lower().strip('_') for col in df.columns]
    df.columns = new_cols

    # b. Remove identifier columns that were not used for training the model
    # We remove these only if they exist to prevent KeyError
    identifier_cols = ['timestamp', 'flow_id', 'src_ip', 'src_port', 'dst_ip', 'created_at'] 
    existing_cols_to_drop = [col for col in identifier_cols if col in df.columns]
    if existing_cols_to_drop:
        # Create a copy to avoid SettingWithCopyWarning, especially important 
        # when the input df is a slice of a larger dataframe.
        df = df.drop(columns=existing_cols_to_drop)

    # c. Handle infinite values and fill any missing data with 0
    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    df.fillna(0, inplace=True)
    
    # d. Ensure the final DataFrame has the exact same feature columns in the
    #    same order as the data the model was trained on.
    training_features = model.feature_names_in_
    for col in training_features:
        if col not in df.columns:
            df[col] = 0  # Add any missing feature columns with a default value of 0
             
    return df[training_features]


# ==============================================================================
# 4. API ENDPOINTS
# ==============================================================================
@app.route('/predict/single', methods=['POST']) # ⭐ CHANGED TO /predict/single
def predict_single():
    """Handles a single prediction request for testing or individual use."""
    if not model or not label_encoder:
        return jsonify({'error': 'Model is not loaded. Please check server logs.'}), 500

    try:
        json_data = request.get_json()
        if not isinstance(json_data, dict):
            return jsonify({'error': 'Input for single prediction must be a single JSON object.'}), 400
            
        features_df = pd.DataFrame([json_data])
        
        # Preprocess the data and make a prediction
        processed_df = preprocess_input(features_df)
        
        # Check if preprocessing resulted in an empty DataFrame
        if processed_df.empty:
            return jsonify({'error': 'Input data resulted in an empty feature set after processing.'}), 400
            
        prediction_encoded = model.predict(processed_df)
        
        # Convert the numeric prediction back to its original text label
        prediction_text = label_encoder.inverse_transform(prediction_encoded)
        
        return jsonify({'prediction': prediction_text[0]})

    except Exception as e:
        print(f"Prediction error in single endpoint: {str(e)}")
        return jsonify({'error': f'Prediction error: {str(e)}'}), 500


@app.route('/predict/batch', methods=['POST']) # ⭐ CHANGED TO /predict/batch
def predict_batch():
    """Handles multiple prediction requests at once for efficiency."""
    if not model or not label_encoder:
        return jsonify({'error': 'Model is not loaded. Please check server logs.'}), 500

    try:
        json_data = request.get_json()
        if not isinstance(json_data, list):
            return jsonify({'error': 'Input for batch prediction must be a list of objects.'}), 400

        features_df = pd.DataFrame(json_data)
        
        # Preprocess the entire batch and predict
        processed_df = preprocess_input(features_df)
        
        # Check if preprocessing resulted in an empty DataFrame
        if processed_df.empty:
            return jsonify({'predictions': []}) # Return empty list if no features to predict
            
        predictions_encoded = model.predict(processed_df)
        
        # Convert all numeric predictions back to their text labels
        predictions_text = label_encoder.inverse_transform(predictions_encoded)
        
        return jsonify({'predictions': predictions_text.tolist()})

    except Exception as e:
        print(f"Prediction error in batch endpoint: {str(e)}")
        return jsonify({'error': f'Prediction error: {str(e)}'}), 500


# ==============================================================================
# 5. RUN THE FLASK APPLICATION
# ==============================================================================
if __name__ == '__main__':
    # Runs the server on localhost, port 5000
    app.run(host='0.0.0.0', port=5000)