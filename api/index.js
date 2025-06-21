const express = require("express");
const mongoose = require("mongoose");
const dotenv = require("dotenv");
const cors = require("cors");
const authRoutes = require("../routes/authRoutes");
const authController = require("../controllers/authController");
const path = require("path");

dotenv.config();

const app = express();

// Trust proxy to get real IP addresses
app.set("trust proxy", true);

// Middleware to capture real IP addresses
app.use((req, res, next) => {
  // Get IP from various sources
  req.realIP =
    req.ip ||
    req.connection.remoteAddress ||
    req.socket.remoteAddress ||
    req.connection.socket?.remoteAddress ||
    req.headers["x-forwarded-for"]?.split(",")[0] ||
    req.headers["x-real-ip"] ||
    "Unknown";

  // Clean up IPv6 addresses and localhost
  if (req.realIP && req.realIP.includes("::ffff:")) {
    req.realIP = req.realIP.replace("::ffff:", "");
  }

  // Convert localhost addresses to more readable format
  if (req.realIP === "::1" || req.realIP === "127.0.0.1") {
    req.realIP = "localhost";
  }

  next();
});

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, "../public")));

// Root route - redirect to login
app.get("/", (req, res) => {
  res.redirect("/login");
});

app.use("/api", authRoutes);

// Serve admin dashboard
app.get("/admin", (req, res) => {
  res.sendFile(path.join(__dirname, "../admin.html"));
});

// Serve registration page
app.get("/register", (req, res) => {
  res.sendFile(path.join(__dirname, "../register.html"));
});

// Serve login page
app.get("/login", (req, res) => {
  res.sendFile(path.join(__dirname, "../login.html"));
});

// Serve settings page
app.get("/settings", (req, res) => {
  res.sendFile(path.join(__dirname, "../settings.html"));
});

// Serve reset password page
app.get("/reset-password", (req, res) => {
  res.sendFile(path.join(__dirname, "../reset-password.html"));
});

app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({
    success: false,
    message: "Something went wrong!",
  });
});

// Connect to MongoDB
const mongoUri =
  process.env.MONGO_URI || "mongodb://localhost:27017/user_auth_system";

mongoose
  .connect(mongoUri)
  .then(async () => {
    console.log("✅ Connected to MongoDB Atlas");

    // Create default superadmin after MongoDB connection
    await authController.createDefaultSuperAdmin();
  })
  .catch((err) => {
    console.error("❌ MongoDB connection error:", err);
  });

// 404 handler
app.use((req, res) => {
  res.status(404).json({
    success: false,
    message: "Route not found",
  });
});

// Export for Vercel
module.exports = app;
