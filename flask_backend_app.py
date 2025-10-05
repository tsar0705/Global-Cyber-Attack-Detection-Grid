from flask import Flask, jsonify
from flask_cors import CORS
import pymssql
import pandas as pd
import numpy as np
import pyodbc
from sklearn.ensemble import IsolationForest

app = Flask(__name__)
CORS(app)

# === 1️⃣ DB Connection Parameters ===
server = 'gcadg-server.database.windows.net'
user = 'CloudSA6615dfe6@gcadg-server'
password = 'tsar28082005@'
database = 'GCADG_SQL_DATABASE'


def get_db_connection():
    try:
        conn_str = (
            "Driver={ODBC Driver 18 for SQL Server};"
            "Server=tcp:gcadg-server.database.windows.net,1433;"
            "Database=GCADG_SQL_DATABASE;"
            "Uid=CloudSA6615dfe6@gcadg-server;" 
            "Pwd=tsar28082005@;"
            "Encrypt=yes;"
            "TrustServerCertificate=no;"
            "Connection Timeout=60;"
        )
        conn = pyodbc.connect(conn_str)
        print("✅ Connected to Azure SQL Database successfully")
        return conn
    except Exception as e:
        print("❌ Failed to connect:", e)
        return None

# === 2️⃣ Fetch data from DB ===
def fetch_attack_data():
    conn = get_db_connection()
    if conn is None:
        return pd.DataFrame()
    cursor = conn.cursor(as_dict=True)
    try:
        cursor.execute("SELECT * FROM cybersecurity_attacks")
        rows = cursor.fetchall()
        df = pd.DataFrame(rows)
        return df
    except Exception as e:
        print("Error fetching data:", e)
        return pd.DataFrame()
    finally:
        cursor.close()
        conn.close()

# === 3️⃣ Preprocess for ML ===
def preprocess(df):
    if df.empty:
        return df

    # Numeric columns
    numeric_cols = ['Source_Port', 'Destination_Port', 'Packet_Length', 'Severity_Level', 'Anomaly_Scores']
    for col in numeric_cols:
        if col in df.columns:
            df[col] = pd.to_numeric(df[col], errors='coerce').fillna(0)

    # Low-cardinality categorical columns
    categorical_cols = [
        'Protocol', 'Packet_Type', 'Traffic_Type', 'Attack_Type', 'Geo_location_Data', 
        'Malware_Indicators'
    ]
    for col in categorical_cols:
        if col in df.columns:
            df[col] = df[col].fillna('unknown').astype('category').cat.codes

    # Encode IPs
    def ip_to_int(ip):
        try:
            return sum([int(x) << (8*(3-i)) for i, x in enumerate(ip.split('.'))])
        except:
            return 0

    if 'Source_IP_Address' in df.columns:
        df['Source_IP_Address'] = df['Source_IP_Address'].fillna('0.0.0.0').apply(ip_to_int)
    if 'Destination_IP_Address' in df.columns:
        df['Destination_IP_Address'] = df['Destination_IP_Address'].fillna('0.0.0.0').apply(ip_to_int)

    # Convert timestamp to numeric
    if 'timestamp' in df.columns:
        df['timestamp'] = pd.to_datetime(df['timestamp'], errors='coerce').astype('int64') // 10**9
        df['timestamp'] = df['timestamp'].fillna(0)

    # Drop large text columns
    text_cols_to_drop = [
        'Payload_Data', 'User_Information', 'Device_Information', 'Network_Segment',
        'Proxy_Information', 'Firewall_Logs', 'IDS_IPS_Alerts', 'Log_Source', 
        'Attack_Signature', 'Action_Taken', 'Alerts_Warnings'
    ]
    df = df.drop(columns=[col for col in text_cols_to_drop if col in df.columns], errors='ignore')

    return df

# === 4️⃣ Train Isolation Forest ===
def train_model(df):
    model = IsolationForest(n_estimators=100, contamination=0.05, random_state=42)
    model.fit(df)
    return model

# === 5️⃣ Detect anomalies ===
def detect_anomalies(model, df):
    df['anomaly'] = model.predict(df)
    anomalies = df[df['anomaly'] == -1]
    return anomalies

# === 6️⃣ Existing Endpoints ===
@app.route('/logs', methods=['GET'])
def get_logs():
    conn = get_db_connection()
    if conn is None:
        return jsonify({'error': 'DB connection failed'}), 500
    cursor = conn.cursor(as_dict=True)
    cursor.execute('''
        SELECT TOP 10 
            [timestamp], [Source_IP_Address], [Destination_IP_Address], 
            [Attack_Type], [Geo_location_Data], [Severity_Level] 
        FROM cybersecurity_attacks 
        ORDER BY [timestamp] DESC
    ''')
    rows = cursor.fetchall()
    cursor.close()
    conn.close()
    return jsonify(rows)

@app.route('/stats', methods=['GET'])
def get_stats():
    conn = get_db_connection()
    if conn is None:
        return jsonify({'error': 'DB connection failed'}), 500
    cursor = conn.cursor(as_dict=True)
    cursor.execute('''
        SELECT [Geo_location_Data] AS region, COUNT(*) AS count 
        FROM cybersecurity_attacks 
        GROUP BY [Geo_location_Data]
    ''')
    region_stats = cursor.fetchall()
    cursor.execute('''
        SELECT [Attack_Type] AS attack_type, COUNT(*) AS count 
        FROM cybersecurity_attacks 
        GROUP BY [Attack_Type]
    ''')
    attack_stats = cursor.fetchall()
    cursor.close()
    conn.close()
    return jsonify({'region_counts': region_stats, 'attack_type_counts': attack_stats})

# === 7️⃣ New /anomalies Endpoint ===
@app.route('/anomalies', methods=['GET'])
def get_anomalies():
    df_raw = fetch_attack_data()   # full dataset with coords + human-readable fields
    if df_raw.empty:
        return jsonify({'error': 'No data found'}), 500

    # Copy for ML
    df_processed = preprocess(df_raw.copy())
    if df_processed.empty:
        return jsonify({'error': 'No valid numeric/categorical columns for anomaly detection'}), 500

    # Train + predict
    model = train_model(df_processed)
    df_raw['anomaly'] = model.predict(df_processed)

    anomalies = df_raw[df_raw['anomaly'] == -1]

    # Only keep necessary columns for frontend
    cols_to_return = [
        'timestamp', 'Source_IP_Address', 'Destination_IP_Address',
        'Attack_Type', 'Severity_Level', 'Geo_location_Data',
        'Latitude', 'Longitude'
    ]
    result = anomalies[cols_to_return].to_dict(orient='records')

    return jsonify({
        'total_logs': len(df_raw),
        'anomalies_detected': len(anomalies),
        'anomalies': result
    })


# === 8️⃣ Run Flask App ===
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5007, debug=True) 
