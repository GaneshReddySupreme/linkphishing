const express = require("express");
const axios = require("axios");
const crypto = require("crypto");
const dotenv = require("dotenv");
const cors = require("cors");

dotenv.config();

const app = express();
app.use(cors()); // Allow all origins by default
app.use(express.json());

// Hashing function as per Web Risk API
const hashUrl = (url) => {
  return crypto.createHash("sha256").update(url).digest("base64");
};

// Route to check URL against Google's Web Risk API
app.post("/check-url", async (req, res) => {
  const { url } = req.body;

  if (!url) {
    return res.status(400).json({ error: "URL is required" });
  }

  try {
    const apiKey = process.env.WEBRISK_API_KEY;
    console.log("Checking URL:", url);
    console.log("Using API Key:", apiKey ? "Yes" : "No");

    const response = await axios.get(
      `https://webrisk.googleapis.com/v1/uris:search?key=${apiKey}&uri=${encodeURIComponent(
        url
      )}`
    );

    const threat = response.data.threat;

    if (threat) {
      return res.json({
        status: "malicious",
        threatTypes: threat.threatTypes,
      });
    } else {
      return res.json({ status: "safe" });
    }
  } catch (err) {
    console.error("🔥 ERROR:", err.response?.data || err.message);
    return res.status(500).json({ error: "Failed to check URL" });
  }
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Web Risk API Server running on http://localhost:${PORT}`);
});
