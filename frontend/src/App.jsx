
import { useState } from "react";
import "./App.css";

const API = "http://127.0.0.1:5000";

export default function App() {
  const [section, setSection] = useState("RSA Encryption");
  const [message, setMessage] = useState("");
  const [ciphertext, setCiphertext] = useState("");
  const [signature, setSignature] = useState("");
  const [result, setResult] = useState("");
  const [loading, setLoading] = useState(false);

  async function callAPI(path, method = "POST", body = null) {
    setLoading(true);
    setResult("");

    try {
      const response = await fetch(API + path, {
        method,
        headers: { "Content-Type": "application/json" },
        ...(body ? { body: JSON.stringify(body) } : {})
      });

      const data = await response.json();

      if (!response.ok) throw new Error(data.error || "Request failed");

      setResult(JSON.stringify(data, null, 2));
      return data;
    } catch (error) {
      setResult("Error: " + error.message);
      return null;
    } finally {
      setLoading(false);
    }
  }

  async function encryptMessage() {
    const data = await callAPI("/rsa/encrypt", "POST", { message });
    if (data) setCiphertext(data.ciphertext);
  }

  async function decryptMessage() {
    await callAPI("/rsa/decrypt", "POST", { ciphertext });
  }

  async function signMessage() {
    const data = await callAPI("/signature/sign", "POST", { message });
    if (data) setSignature(data.signature);
  }

  async function verifySignature() {
    await callAPI("/signature/verify", "POST", { message, signature });
  }

  const sections = [
    "RSA Encryption",
    "RSA Decryption",
    "Diffie-Hellman",
    "Digital Signature",
    "SHA-512 Hashing",
    "X.509 Certificate"
  ];

  async function runSection() {
    if (section === "Diffie-Hellman") {
      await callAPI("/dh/exchange", "GET");
    } else if (section === "SHA-512 Hashing") {
      await callAPI("/hash", "POST", { message });
    } else if (section === "X.509 Certificate") {
      await callAPI("/certificate", "GET");
    } else if (section === "RSA Encryption") {
      await encryptMessage();
    } else if (section === "RSA Decryption") {
      await decryptMessage();
    } else {
      await signMessage();
    }
  }

  return (
    <div className="app">
      <aside className="sidebar">
        <h2>🔐 CryptoVault</h2>
        <p className="muted">Cryptography Toolkit</p>

        {sections.map((item) => (
          <button
            key={item}
            className={section === item ? "nav active" : "nav"}
            onClick={() => {
              setSection(item);
              setResult("");
            }}
          >
            {item}
          </button>
        ))}
      </aside>

      <main className="main">
        <header>
          <div>
            <h1>CryptoVault Dashboard</h1>
            <p>Explore encryption, hashing and digital signatures.</p>
          </div>
          <span className="status">● Backend connected*</span>
        </header>

        <div className="cards">
          <div className="card">
            <span>01</span>
            <h3>RSA</h3>
            <p>Public-key encryption and decryption</p>
          </div>
          <div className="card">
            <span>02</span>
            <h3>Digital Signatures</h3>
            <p>Sign and verify message integrity</p>
          </div>
          <div className="card">
            <span>03</span>
            <h3>SHA-512</h3>
            <p>Generate a cryptographic hash</p>
          </div>
        </div>

        <section className="workspace">
          <h2>{section}</h2>
          <p className="muted">
            Choose a function, enter your data and run the operation.
          </p>

          {section !== "Diffie-Hellman" &&
            section !== "X.509 Certificate" && (
              <>
                <label>Plaintext message</label>
                <textarea
                  value={message}
                  onChange={(e) => setMessage(e.target.value)}
                  placeholder="Enter your message here..."
                />
              </>
            )}

          {section === "RSA Decryption" && (
            <>
              <label>Base64 ciphertext</label>
              <textarea
                value={ciphertext}
                onChange={(e) => setCiphertext(e.target.value)}
                placeholder="Paste ciphertext from RSA Encryption"
              />
            </>
          )}

          {section === "Digital Signature" && (
            <>
              <label>Digital signature (Base64)</label>
              <textarea
                value={signature}
                onChange={(e) => setSignature(e.target.value)}
                placeholder="Sign first, then verify the signature"
              />
              <button className="secondary" onClick={verifySignature}>
                Verify Signature
              </button>
            </>
          )}

          <button className="primary" onClick={runSection} disabled={loading}>
            {loading ? "Processing..." : "Run " + section}
          </button>

          {section === "RSA Encryption" && ciphertext && (
            <div className="output">
              <h3>Ciphertext (Base64)</h3>
              <pre>{ciphertext}</pre>
              <button
                className="secondary"
                onClick={() => {
                  setSection("RSA Decryption");
                }}
              >
                Go to Decryption
              </button>
            </div>
          )}

          {section === "Digital Signature" && signature && (
            <div className="output">
              <h3>Digital Signature (Base64)</h3>
              <pre>{signature}</pre>
            </div>
          )}

          {result && (
            <div className="output">
              <h3>Result</h3>
              <pre>{result}</pre>
            </div>
          )}
        </section>

        <p className="footer">
          CryptoVault · Educational cryptography demonstration
        </p>
      </main>
    </div>
  );
}
