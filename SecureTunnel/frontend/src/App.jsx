
import { useEffect, useState } from "react";
import "./App.css";

const API = "http://127.0.0.1:5001";

export default function App() {
  const [mode, setMode] = useState("tls");
  const [steps, setSteps] = useState([]);
  const [current, setCurrent] = useState(0);
  const [ipsec, setIpsec] = useState({});
  const [error, setError] = useState("");

  useEffect(() => {
    async function loadData() {
      try {
        setError("");
        const endpoint = mode === "tls" ? "/api/tls" : "/api/ssh";
        const response = await fetch(API + endpoint);
        if (!response.ok) throw new Error("Could not load data");
        const data = await response.json();
        setSteps(data.steps);
        setCurrent(0);

        const ipsecResponse = await fetch(API + "/api/ipsec");
        if (!ipsecResponse.ok) throw new Error("Could not load IPsec data");
        setIpsec(await ipsecResponse.json());
      } catch {
        setError("Backend unavailable. Start the Flask server on port 5001.");
      }
    }
    loadData();
  }, [mode]);

  const selected = steps[current];

  return (
    <div className="app">
      <aside className="sidebar">
        <h2>🔐 SecureTunnel</h2>
        <p>Network Security Lab</p>

        <button
          className={mode === "tls" ? "nav active" : "nav"}
          onClick={() => setMode("tls")}
        >
          TLS Handshake
        </button>

        <button
          className={mode === "ssh" ? "nav active" : "nav"}
          onClick={() => setMode("ssh")}
        >
          SSH Connection
        </button>

        <button
          className={mode === "ipsec" ? "nav active" : "nav"}
          onClick={() => setMode("ipsec")}
        >
          IPsec Modes
        </button>
      </aside>

      <main className="main">
        <header>
          <h1>SecureTunnel Visualizer</h1>
          <p>Explore secure communication step by step.</p>
        </header>

        {error && <div className="error">{error}</div>}

        {mode !== "ipsec" && !error && (
          <section className="panel">
            <span className="tag">
              {mode === "tls" ? "TLS / SSL" : "SSH PROTOCOL"}
            </span>

            <h2>
              {mode === "tls"
                ? "TLS Handshake"
                : "SSH Connection Establishment"}
            </h2>

            <div className="progress">
              {steps.map((step, index) => (
                <button
                  key={step.step}
                  className={index === current ? "step active-step" : "step"}
                  onClick={() => setCurrent(index)}
                  title={step.title}
                >
                  {index + 1}
                </button>
              ))}
            </div>

            {selected && (
              <div className="step-content">
                <p className="muted">
                  STEP {selected.step} OF {steps.length}
                </p>
                <h3>{selected.title}</h3>
                <p>{selected.description}</p>
              </div>
            )}

            <div className="actions">
              <button
                className="secondary"
                disabled={current === 0}
                onClick={() => setCurrent(current - 1)}
              >
                Previous
              </button>

              <button
                className="primary"
                disabled={current >= steps.length - 1}
                onClick={() => setCurrent(current + 1)}
              >
                Next Step →
              </button>
            </div>

            <p className="muted">
              This is an educational protocol simulation, not a live connection.
            </p>
          </section>
        )}

        {mode === "ipsec" && (
          <section className="panel">
            <span className="tag">IP SECURITY</span>
            <h2>IPsec: Transport vs Tunnel</h2>

            <div className="comparison">
              <article className="mode-card">
                <h3>Transport Mode</h3>
                <div className="packet">
                  <span>Original IP Header</span>
                  <span className="protected">Protected Payload</span>
                </div>
                <p>
                  {ipsec.transport?.description ||
                    "Protects the IP payload while retaining the original IP header."}
                </p>
              </article>

              <article className="mode-card">
                <h3>Tunnel Mode</h3>
                <div className="packet">
                  <span>New IP Header</span>
                  <span className="protected">Protected Original Packet</span>
                </div>
                <p>
                  {ipsec.tunnel?.description ||
                    "Protects the entire original packet inside a new IP packet."}
                </p>
              </article>
            </div>
          </section>
        )}

        <footer>SecureTunnel · Network Security Educational Project</footer>
      </main>
    </div>
  );
}
