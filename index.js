require("dotenv").config();
const express = require("express");
const cors = require("cors");

const app = express();

// CORS: allow the client origin if configured, otherwise allow all (dev).
app.use(
  cors({
    origin: process.env.CLIENT_URL || true,
    credentials: true,
  })
);
app.use(express.json());

// Health check — must NOT touch the DB, so it works even without a valid MONGODB_URI.
app.get("/", (req, res) => {
  res.json({ status: "ok", message: "BookNook server is running" });
});

// 404 for unknown routes.
app.use((req, res) => {
  res.status(404).json({ error: "Route not found" });
});

// Central error handler — always return JSON, never crash the process.
app.use((err, req, res, next) => {
  console.error(err);
  res.status(err.status || 500).json({ error: err.message || "Internal server error" });
});

// Only listen when run directly; Vercel serverless imports the app without listening.
if (require.main === module) {
  const PORT = process.env.PORT || 5000;
  app.listen(PORT, () => {
    console.log(`BookNook server is running on port ${PORT}`);
  });
}

module.exports = app;
