const express = require("express");
const cors = require("cors");
const { WebRiskServiceClient } = require("@google-cloud/web-risk");

const app = express();
const PORT = process.env.PORT || 5000;

app.use(cors());

// Initialize the Web Risk client with your service account key
const client = new WebRiskServiceClient({
  keyFilename: "./key.json", // Path to your service account key
});

// API endpoint: /check-url?url=https://example.com
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
