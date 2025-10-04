from flask import Flask, request, jsonify
import pandas as pd
import joblib
import numpy as np

app = Flask(__name__)

# Load the trained model
model = joblib.load("model/anomaly_model.pkl")

# Preprocess incoming data
def preprocess(df):
    numeric_cols = ['Source_Port', 'Destination_Port', 'Packet_Length', 'Severity_Level', 'Anomaly_Scores']
    for col in numeric_cols:
        if col in df.columns:
            df[col] = pd.to_numeric(df[col], errors='coerce').fillna(0)
    
    # Convert IPs to integers
    def ip_to_int(ip):
        try:
            return sum([int(x) << (8*(3-i)) for i, x in enumerate(ip.split('.'))])
        except:
            return 0

    for col in ['Source_IP_Address', 'Destination_IP_Address']:
        if col in df.columns:
            df[col] = df[col].fillna('0.0.0.0').apply(ip_to_int)

    return df

@app.route("/predict", methods=["POST"])
def predict():
    data = request.get_json()
    df = pd.DataFrame(data)
    df_processed = preprocess(df)
    preds = model.predict(df_processed)
    df['anomaly'] = preds
    result = df.to_dict(orient='records')
    return jsonify(result)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
