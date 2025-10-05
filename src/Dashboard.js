// Dashboard.js
import React, { useEffect, useState, useRef } from "react";
import { MapContainer, TileLayer, Marker, Popup } from "react-leaflet";
import "leaflet/dist/leaflet.css";
import L from "leaflet";
import InfiniteScroll from "react-infinite-scroll-component";
import { withAITracking } from "@microsoft/applicationinsights-react-js";
import { reactPlugin } from "./appInsights";
import 'bootstrap/dist/css/bootstrap.min.css';

// Fix default marker icons
delete L.Icon.Default.prototype._getIconUrl;
L.Icon.Default.mergeOptions({
  iconRetinaUrl:
    "https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.7.1/images/marker-icon-2x.png",
  iconUrl:
    "https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.7.1/images/marker-icon.png",
  shadowUrl:
    "https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.7.1/images/marker-shadow.png",
});

function Dashboard() {
  const [displayedLogs, setDisplayedLogs] = useState([]);
  const [regionCounts, setRegionCounts] = useState([]);
  const [attackTypeCounts, setAttackTypeCounts] = useState([]);
  const [anomalies, setAnomalies] = useState([]);
  const [hasMore, setHasMore] = useState(true);

  const nextIndex = useRef(0);
  const allLogs = useRef([]);
  const batchSize = 10;

  // Load more logs for infinite scroll
  const loadMoreLogs = () => {
    const logs = allLogs.current;
    if (!Array.isArray(logs) || logs.length === 0) {
      setHasMore(false);
      return;
    }
    const start = nextIndex.current;
    const end = start + batchSize;
    const nextLogs = logs.slice(start, end);
    setDisplayedLogs((prev) => [...prev, ...nextLogs]);
    nextIndex.current = end;
    if (end >= logs.length) setHasMore(false);
  };

  // Fetch stats from backend
  const fetchStats = () => {
    fetch("http://127.0.0.1:5008/stats")
      .then((res) => res.json())
      .then((data) => {
        setRegionCounts(data.region_counts || []);
        setAttackTypeCounts(data.attack_type_counts || []);
      })
      .catch(() => {
        setRegionCounts([]);
        setAttackTypeCounts([]);
      });
  };

  // Fetch logs from backend
  const fetchLogs = () => {
    fetch("http://127.0.0.1:5008/logs")
      .then((res) => res.json())
      .then((data) => {
        allLogs.current = Array.isArray(data) ? data : [];
        setDisplayedLogs(allLogs.current.slice(0, batchSize));
        nextIndex.current = batchSize;
        setHasMore(allLogs.current.length > batchSize);
      })
      .catch(() => {
        allLogs.current = [];
        setDisplayedLogs([]);
        setHasMore(false);
      });
  };

  // Fetch anomalies from backend
  const fetchAnomalies = () => {
    fetch("http://127.0.0.1:5008/anomalies")
      .then((res) => res.json())
      .then((data) => {
        setAnomalies(data.anomalies || []);
      })
      .catch(() => setAnomalies([]));
  };

  // Auto-refresh every 30s
  useEffect(() => {
    fetchLogs();
    fetchStats();
    fetchAnomalies();

    const intervalId = setInterval(() => {
      nextIndex.current = 0;
      setDisplayedLogs([]);
      setHasMore(true);
      fetchLogs();
      fetchStats();
      fetchAnomalies();
    }, 30000);

    return () => clearInterval(intervalId);
  }, []);

  return (
    <div className="container my-4" style={{ fontFamily: "Arial, sans-serif" }}>
      <h1 className="mb-4">Global Cyber Attack Dashboard</h1>

      {/* Stats section */}
      <div className="row mb-4">
        <div className="col-md-6">
          <div className="card border-primary h-100">
            <div className="card-header bg-primary text-white">Counts by Region</div>
            <ul className="list-group list-group-flush">
              {regionCounts.length === 0 ? (
                <li className="list-group-item">No data</li>
              ) : (
                regionCounts.map(({ region, count }, idx) => (
                  <li className="list-group-item" key={idx}>
                    {region}: {count}
                  </li>
                ))
              )}
            </ul>
          </div>
        </div>

        <div className="col-md-6">
          <div className="card border-success" style={{ minWidth: 220 }}>
            <div className="card-header bg-success text-white">Counts by Attack Type</div>
            <ul className="list-group list-group-flush">
              {attackTypeCounts.length === 0 ? (
                <li className="list-group-item">No data</li>
              ) : (
                attackTypeCounts.map(({ attack_type, count }, idx) => (
                  <li className="list-group-item" key={idx}>
                    {attack_type}: {count}
                  </li>
                ))
              )}
            </ul>
          </div>
        </div>
      </div>

      {/* Logs table */}
      <h2>
        Recent Logs <small className="text-danger">Anomalies Highlighted</small>
      </h2>
      <InfiniteScroll
        dataLength={displayedLogs.length}
        next={loadMoreLogs}
        hasMore={hasMore}
        loader={<h6>Loading more logs...</h6>}
        endMessage={
          <p className="text-center">
            <b>No more logs</b>
          </p>
        }
        height={400}
      >
        <table className="table table-striped table-bordered mb-0">
          <thead className="table-dark">
            <tr>
              <th>Timestamp</th>
              <th>Source IP</th>
              <th>Destination IP</th>
              <th>Attack Type</th>
              <th>Region</th>
              <th>Severity</th>
              <th>Anomaly</th>
            </tr>
          </thead>
          <tbody>
            {displayedLogs.map((log, idx) => {
              const isAnomaly = anomalies.find(
                (a) => a.timestamp === log.timestamp
              );
              return (
                <tr key={idx} className={isAnomaly ? "table-danger" : ""}>
                  <td>{log.Timestamp}</td>
                  <td>{log["Source IP Address"]}</td>
                  <td>{log["Destination IP Address"]}</td>
                  <td>{log["Attack Type"]}</td>
                  <td>{log["Geo-location Data"]}</td>
                  <td>{log["Severity Level"]}</td>
                  <td>{isAnomaly ? "⚠️" : ""}</td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </InfiniteScroll>

      {/* Anomaly Map */}
      <h2 className="mt-5">Global Anomaly Map</h2>
      <MapContainer
        center={[20, 0]}
        zoom={2}
        style={{ height: 400, width: "100%" }}
      >
        <TileLayer url="https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png" />
        {anomalies
          .filter((a) => a.Latitude && a.Longitude)
          .map((a, idx) => (
            <Marker key={idx} position={[a.Latitude, a.Longitude]}>
              <Popup>
                <div>
                  <b>Attack Type:</b> {a["Attack_Type"]}
                  <br />
                  <b>Severity:</b> {a["Severity_Level"]}
                  <br />
                  <b>Source IP:</b> {a["Source_IP_Address"]}
                  <br />
                  <b>Destination IP:</b> {a["Destination_IP_Address"]}
                </div>
              </Popup>
            </Marker>
          ))}
      </MapContainer>
    </div>
  );
}


export default withAITracking(reactPlugin, Dashboard);
