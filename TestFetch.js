import React, { useEffect, useState } from "react";

function TestFetch() {
  const [data, setData] = useState(null);
  const [error, setError] = useState(null);

  useEffect(() => {
    fetch("http://localhost:5000/logs")
      .then((res) => {
        if (!res.ok) {
          throw new Error(`HTTP error! status: ${res.status}`);
        }
        return res.json();
      })
      .then((json) => setData(json))
      .catch((err) => setError(err.message));
  }, []);

  if (error) return <p style={{ color: "red" }}>Error: {error}</p>;
  if (!data) return <p>Loading...</p>;

  return (
    <div>
      <h2>Test Fetch Output</h2>
      <pre style={{ textAlign: "left", background: "#f4f4f4", padding: "10px" }}>
        {JSON.stringify(data, null, 2)}
      </pre>
    </div>
  );
}

export default TestFetch;
