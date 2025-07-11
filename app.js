const fs = require("fs");
const path = require("path");
const { WebRiskServiceClient } = require("@google-cloud/web-risk");
const express = require("express");
const cors = require("cors");

const app = express();
const PORT = process.env.PORT || 5000;

app.use(cors());

// Decode base64 env and write to temp file
const keyPath = path.join("/tmp", "key.json");
fs.writeFileSync(keyPath, Buffer.from(process.env.GOOGLE_APPLICATION_CREDENTIALS_BASE64, "base64"));

const client = new WebRiskServiceClient({
  keyFilename: keyPath,
});

app.get("/check-url", async (req, res) => {
  const inputUrl = req.query.url;

  if (!inputUrl) {
    return res.status(400).json({ error: "Missing URL parameter" });
  }

  try {
    const [response] = await client.searchUris({
      uri: inputUrl,
      threatTypes: ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
    });

    const isSafe = !response.threat;

    res.json({
      url: inputUrl,
      safe: isSafe,
      threat: response.threat || null,
    });
  } catch (err) {
    console.error("Error checking URL:", err.message);
    res.status(500).json({ error: "Failed to check URL" });
  }
});

app.listen(PORT, () => {
  console.log(`✅ Web Risk API running at http://localhost:${PORT}`);
});
