const config = require("config");
const express = require("express");
const morgan = require("morgan");

const app = express();

try {
  // Import startup modules
  require("./startup/prod.js")(app);
  require("./startup/db.startup.js")();
  require("./startup/logger.startup.js")();
  // API routes
  require("./startup/routes.startup")(app);
  console.log("Startup completed successfully");
} catch (err) {
  console.error("Error during startup:", err);
}

// Logging middleware
if (config.util.getEnv("NODE_ENV") !== "test") {
  app.use(morgan("combined"));
}

// Health check endpoint
app.get("/health", (req, res) => {
  res.status(200).json({
    status: "success",
    message: "Ekub App Backend is running",
    timestamp: new Date().toISOString(),
    environment: config.util.getEnv("NODE_ENV"),
    version: require("./package.json").version,
  });
});

// 404 handler
app.use("*", (req, res) => {
  res.status(404).json({
    status: "error",
    error: {
      code: "not-found",
      message: "The requested resource was not found",
    },
  });
});

// Use dynamic port configuration
const port = config.get("server.port") || process.env.PORT || 3001;
const server = app.listen(port, config.get("server.host") || "0.0.0.0", () => {
  console.log(`🚀 Ekub App Backend is running on port ${port}`);
  console.log(`🌍 Environment: ${config.util.getEnv("NODE_ENV")}`);
  console.log(`🔗 Health check: ${config.get("database.url")}:${port}/health`);
});

// Graceful shutdown
process.on("SIGTERM", () => {
  console.log("SIGTERM received, shutting down gracefully");
  server.close(() => process.exit(0));
});

process.on("SIGINT", () => {
  console.log("SIGINT received, shutting down gracefully");
  server.close(() => process.exit(0));
});

module.exports = app;
