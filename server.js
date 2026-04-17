const express = require("express");
const dotenv = require("dotenv");
const cors = require("cors");
const authRoutes = require("./routes/authRoutes");
const authController = require("./controllers/authController");
const { connectMongoDB } = require("./utils/mongoConnection");

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
app.use(express.static("public"));

// Root route - redirect to login
app.get("/", (req, res) => {
  res.redirect("/login");
});

app.use("/api", authRoutes);

// Serve admin dashboard
app.get("/admin", (req, res) => {
  res.sendFile(__dirname + "/admin.html");
});

// Serve registration page
app.get("/register", (req, res) => {
  res.sendFile(__dirname + "/register.html");
});

// Serve login page
app.get("/login", (req, res) => {
  res.sendFile(__dirname + "/login.html");
});

// Serve settings page
app.get("/settings", (req, res) => {
  res.sendFile(__dirname + "/settings.html");
});

// Serve reset password page
app.get("/reset-password", (req, res) => {
  res.sendFile(__dirname + "/reset-password.html");
});

app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({
    success: false,
    message: "Something went wrong!",
  });
});

// Connect to MongoDB
connectMongoDB({
  defaultUri: "mongodb://127.0.0.1:27017/user_auth_system",
})
  .then(async ({ hostname }) => {
    console.log(`✅ Connected to MongoDB (${hostname})`);

    // Create default superadmin after MongoDB connection
    await authController.createDefaultSuperAdmin();

    const PORT = process.env.PORT || 5000;
    app.listen(PORT, () => {
      console.log(`🚀 Server running on port ${PORT}`);
      console.log(`🔐 Login: http://localhost:${PORT}/login`);
      console.log(`📧 Admin Dashboard: http://localhost:${PORT}/admin`);
      console.log(`📝 Registration: http://localhost:${PORT}/register`);
      console.log(`⚙️ Settings: http://localhost:${PORT}/settings`);
    });
  })
  .catch((err) => {
    console.error("❌ MongoDB connection error:", err.message || err);
  });

// 404 handler
app.use((req, res) => {
  res.status(404).json({
    success: false,
    message: "Route not found",
  });
});
