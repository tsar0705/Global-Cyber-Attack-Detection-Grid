// App.js
import React from "react";
import { Routes, Route } from "react-router-dom";
import Dashboard from "./Dashboard"; // the Dashboard we just created

function App() {
  return (
    <Routes>
      <Route path="/" element={<Dashboard />} />
      {/* You can add more routes here if needed */}
    </Routes>
  );
}

export default App;
