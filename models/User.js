const mongoose = require("mongoose");

const activityLogSchema = new mongoose.Schema({
  action: {
    type: String,
    required: true,
    enum: [
      "login",
      "logout",
      "password_reset",
      "otp_verification",
      "registration",
      "password_change",
      "user_ban",
      "user_unban",
      "user_status_update",
      "admin_creation",
      "user_creation",
      "admin_deletion",
      "user_deletion",
      "superadmin_creation",
      "logs_deletion",
      "log_deletion",
      "gemini_key_update",
      "gemini_key_validation",
      "send_reset_url",
    ],
  },
  timestamp: {
    type: Date,
    default: Date.now,
  },
  ipAddress: String,
  userAgent: String,
  status: {
    type: String,
    enum: ["success", "failed"],
    default: "success",
  },
  note: String,
});

const userSchema = new mongoose.Schema(
  {
    name: {
      type: String,
      required: true,
      trim: true,
    },
    email: {
      type: String,
      required: true,
      unique: true,
      lowercase: true,
      trim: true,
    },
    password: {
      type: String,
      required: true,
    },
    otp: {
      type: String,
    },
    otpExpiry: {
      type: Date,
    },
    isVerified: {
      type: Boolean,
      default: false,
    },
    // Forgot password fields
    resetPasswordToken: String,
    resetPasswordExpiry: Date,
    // Activity tracking
    lastLogin: Date,
    loginCount: {
      type: Number,
      default: 0,
    },
    activityLogs: [activityLogSchema],
    // Admin fields
    isAdmin: {
      type: Boolean,
      default: false,
    },
    isSuperAdmin: {
      type: Boolean,
      default: false,
    },
    status: {
      type: String,
      enum: ["active", "suspended", "pending", "banned"],
      default: "pending",
    },
    banned: {
      type: Boolean,
      default: false,
    },
    bannedBy: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
    },
    bannedAt: Date,
    banReason: String,
    // Gemini API Key
    geminiApiKey: {
      type: String,
      default: null,
    },
    geminiKeyValid: {
      type: Boolean,
      default: false,
    },
    geminiKeyLastValidated: Date,
  },
  { timestamps: true }
);

module.exports = mongoose.model("User", userSchema);
