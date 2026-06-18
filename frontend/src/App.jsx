import React from "react";
import { createRoot } from "react-dom/client";

function App() {
  return (
    <main style={{ fontFamily: "Arial, sans-serif", padding: "40px" }}>
      <h1>CyberMeters</h1>
      <p>Cloud-native Cyber MOT and Attack Surface Management platform.</p>

      <section>
        <h2>Platform Capabilities</h2>
        <ul>
          <li>Attack Surface Discovery</li>
          <li>Hidden Asset Intelligence</li>
          <li>CISA KEV Intelligence</li>
          <li>Executive Risk Reporting</li>
          <li>Remediation Prioritization</li>
        </ul>
      </section>
    </main>
  );
}

createRoot(document.getElementById("root")).render(<App />);
