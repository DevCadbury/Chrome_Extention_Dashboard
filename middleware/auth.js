const jwt = require("jsonwebtoken");
const User = require("../models/User");

// JWT Authentication middleware
const authenticateToken = async (req, res, next) => {
  try {
    const authHeader = req.headers["authorization"];
    const token = authHeader && authHeader.split(" ")[1]; // Bearer TOKEN

    if (!token) {
      return res.status(401).json({
        success: false,
        message: "Access token required",
      });
    }

    const decoded = jwt.verify(
      token,
      process.env.JWT_SECRET || "your-secret-key"
    );
    const user = await User.findById(decoded.userId).select("-password");

    if (!user) {
      return res.status(401).json({
        success: false,
        message: "Invalid token",
      });
    }

    if (user.banned) {
      return res.status(403).json({
        success: false,
        message: "Account is banned",
      });
    }

    // Check if session token is still valid (for session termination)
    if (!user.sessionToken) {
      return res.status(401).json({
        success: false,
        message: "Session expired. Please login again.",
      });
    }

    // Check if the session token in JWT matches the current session token
    if (decoded.sessionToken !== user.sessionToken) {
      return res.status(401).json({
        success: false,
        message: "Session expired. Please login again.",
      });
    }

    req.user = user;
    next();
  } catch (error) {
    return res.status(403).json({
      success: false,
      message: "Invalid token",
    });
  }
};

// Admin middleware
const requireAdmin = (req, res, next) => {
  if (!req.user.isAdmin && !req.user.isSuperAdmin) {
    return res.status(403).json({
      success: false,
      message: "Admin access required",
    });
  }
  next();
};

// Super Admin middleware
const requireSuperAdmin = (req, res, next) => {
  if (!req.user.isSuperAdmin) {
    return res.status(403).json({
      success: false,
      message: "Super admin access required",
    });
  }
  next();
};

// Verified user middleware
const requireVerified = (req, res, next) => {
  if (!req.user.isVerified) {
    return res.status(403).json({
      success: false,
      message: "Email verification required",
    });
  }
  next();
};

module.exports = {
  authenticateToken,
  requireAdmin,
  requireSuperAdmin,
  requireVerified,
};
