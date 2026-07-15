# 🌐 Global Cyber Attack Detection Grid (GCADG)

A full-stack dashboard for monitoring, visualizing, and detecting anomalies in global cybersecurity attack data. The app combines a **React + Leaflet** frontend with a **Flask + scikit-learn** backend that pulls live attack logs from an Azure SQL Database and flags unusual activity in real time using unsupervised machine learning.

![React](https://img.shields.io/badge/Frontend-React_19-61DAFB?logo=react&logoColor=white)
![Flask](https://img.shields.io/badge/Backend-Flask-000000?logo=flask&logoColor=white)
![scikit-learn](https://img.shields.io/badge/ML-Isolation_Forest-F7931E?logo=scikit-learn&logoColor=white)
![Azure SQL](https://img.shields.io/badge/Database-Azure_SQL-0078D4?logo=microsoftazure&logoColor=white)

---

## 📖 Overview

GCADG ingests network/security log data stored in Azure SQL, then:

- Displays recent attack logs in a live, infinitely-scrolling table
- Aggregates attack counts by **region** and **attack type**
- Runs an **Isolation Forest** anomaly detection model against incoming logs to surface suspicious events
- Plots detected anomalies on an interactive **world map** (Leaflet + OpenStreetMap) using each event's geolocation
- Auto-refreshes every 30 seconds so the dashboard stays current without a manual reload

## ✨ Features

| Feature | Description |
|---|---|
| 📊 **Live stats panel** | Real-time counts of attacks grouped by region and by attack type |
| 📜 **Scrolling log table** | Infinite-scroll table of recent logs, with anomalous rows highlighted |
| 🧠 **ML-based anomaly detection** | Isolation Forest model trained on-the-fly against numeric/categorical log features |
| 🗺️ **Global anomaly map** | Interactive map markers for each detected anomaly, with attack details in popups |
| 🔄 **Auto-refresh** | Dashboard re-fetches logs, stats, and anomalies every 30 seconds |
| 📈 **Telemetry** | Frontend instrumented with Azure Application Insights (React plugin) |

## 🏗️ Architecture

```
┌─────────────────────┐        REST (JSON)        ┌──────────────────────┐
│   React Frontend     │ ─────────────────────────▶ │   Flask Backend       │
│  (Dashboard, Leaflet, │ ◀───────────────────────── │  (flask_backend_app.py)│
│   Bootstrap, App      │                            │                       │
│   Insights)           │                            └──────────┬────────────┘
└─────────────────────┘                                       │
                                                                 │ pyodbc / pymssql
                                                                 ▼
                                                   ┌─────────────────────────┐
                                                   │   Azure SQL Database     │
                                                   │  (cybersecurity_attacks) │
                                                   └─────────────────────────┘
```

**Backend endpoints:**

| Endpoint | Method | Description |
|---|---|---|
| `/logs` | `GET` | Returns the 10 most recent attack log entries |
| `/stats` | `GET` | Returns aggregate counts by region and by attack type |
| `/anomalies` | `GET` | Runs Isolation Forest over the full dataset and returns detected anomalies with coordinates |

## 🛠️ Tech Stack

**Frontend**
- React 19, React Router
- React-Leaflet / Leaflet (mapping)
- Bootstrap 5
- React Infinite Scroll Component
- Azure Application Insights (React plugin)

**Backend**
- Flask + Flask-CORS
- pandas, NumPy
- scikit-learn (`IsolationForest`)
- pyodbc / pymssql (Azure SQL connectivity)

**Data**
- Azure SQL Database table: `cybersecurity_attacks`

## 🚀 Getting Started

### Prerequisites

- Node.js (v18+) and npm
- Python 3.9+
- [ODBC Driver 18 for SQL Server](https://learn.microsoft.com/en-us/sql/connect/odbc/download-odbc-driver-for-sql-server) installed locally
- Access to an Azure SQL Database with a `cybersecurity_attacks` table

### 1. Clone the repository

```bash
git clone https://github.com/tsar0705/Global-Cyber-Attack-Detection-Grid.git
cd Global-Cyber-Attack-Detection-Grid
```

### 2. Backend setup

```bash
pip install flask flask-cors pyodbc pymssql pandas numpy scikit-learn
```

> ⚠️ **Note:** `requirements.txt` in this repo is currently incomplete — it doesn't list `flask-cors`, `pymssql`, `pandas`, `numpy`, or `scikit-learn`, all of which `flask_backend_app.py` imports. Install them manually as shown above, or update `requirements.txt` to match.

Configure your database credentials as environment variables rather than hardcoding them in `flask_backend_app.py`:

```bash
export DB_SERVER="your-server.database.windows.net"
export DB_NAME="your-database-name"
export DB_USER="your-username"
export DB_PASSWORD="your-password"
```

> 🔒 **Security note:** The current version of `flask_backend_app.py` has database credentials hardcoded directly in the source. Since this is a public repository, **rotate any exposed credentials immediately** and refactor the connection logic to read from environment variables (e.g. via `python-dotenv`) before deploying or sharing this code further.

Run the backend:

```bash
python flask_backend_app.py
```

The API will be available at `http://127.0.0.1:5007` (update the port in the frontend fetch calls if you change it — some components currently point to `5008`, so double-check consistency between `flask_backend_app.py` and `src/Dashboard.js`).

### 3. Frontend setup

```bash
npm install
npm start
```

The app will open at `http://localhost:3000`.

## 📁 Project Structure

```
├── src/
│   ├── App.js              # Root component with routing
│   ├── Dashboard.js        # Main dashboard: stats, logs table, anomaly map
│   ├── appInsights.js      # Azure Application Insights setup
│   ├── TestFetch.js        # Simple test component for API connectivity
│   └── index.js            # App entry point
├── public/                 # Static assets
├── build/                  # Production build output
├── flask_backend_app.py    # Flask API: DB access, preprocessing, anomaly detection
├── requirements.txt        # Python dependencies (see note above)
├── package.json            # Node dependencies and scripts
└── README.md
```

## 🧪 Available Scripts

In the project directory, you can run:

- `npm start` – Runs the app in development mode at `http://localhost:3000`
- `npm test` – Launches the test runner in watch mode
- `npm run build` – Builds the app for production into the `build/` folder
- `npm run eject` – Ejects the Create React App configuration (one-way operation)

## 🗺️ Roadmap Ideas

- [ ] Move DB credentials fully to environment variables / a secrets manager
- [ ] Align backend and frontend on a single port configuration
- [ ] Add authentication for the API endpoints
- [ ] Cache/persist trained anomaly model instead of retraining per request
- [ ] Add automated tests for the Flask endpoints

## 📄 License

No license file is currently included in this repository. Consider adding one (e.g. MIT) if you intend for others to use or contribute to this project.

## 🙋 About

Built as a project exploring real-time cybersecurity monitoring, geospatial visualization, and unsupervised anomaly detection using an Azure-backed data pipeline.
