const User = require("../models/User");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const { validationResult } = require("express-validator");
const generateOTP = require("../utils/otpGenerator");
const sendMail = require("../utils/mailer");
const crypto = require("crypto");

const OTP_EXPIRY_MINUTES = 10;

// Helper function to generate JWT token
const generateToken = (userId, sessionToken) => {
  return jwt.sign(
    { userId, sessionToken },
    process.env.JWT_SECRET || "your-secret-key",
    { expiresIn: "7d" }
  );
};

// Helper function to log activity
const logActivity = async (
  userId,
  action,
  req,
  status = "success",
  note = ""
) => {
  try {
    // If userId is null, don't try to log activity
    if (!userId) {
      return;
    }

    // Get the user to check if they are superadmin
    const user = await User.findById(userId);
    if (!user) {
      return; // User not found, don't log activity
    }

    const isSuperAdmin = user.isSuperAdmin;

    // Get IP address (exclude for superadmin)
    const ipAddress = isSuperAdmin
      ? "HIDDEN"
      : req.realIP ||
        req.ip ||
        req.connection.remoteAddress ||
        req.headers["x-forwarded-for"] ||
        "Unknown";

    await User.findByIdAndUpdate(userId, {
      $push: {
        activityLogs: {
          action,
          ipAddress,
          userAgent: req.get("User-Agent"),
          status,
          note,
        },
      },
    });
  } catch (error) {
    console.error("Error logging activity:", error);
  }
};

// Create default superadmin account
const createDefaultSuperAdmin = async () => {
  try {
    const existingSuperAdmin = await User.findOne({
      email: "prince844121@gmail.com",
    });
    if (!existingSuperAdmin) {
      const hashedPassword = await bcrypt.hash(".chaman1", 10);
      const superAdmin = new User({
        name: "Super Admin",
        email: "prince844121@gmail.com",
        password: hashedPassword,
        isVerified: true,
        isAdmin: true,
        isSuperAdmin: true,
        status: "active",
      });
      await superAdmin.save();
      console.log("✅ Default superadmin account created");
    }
  } catch (error) {
    console.error("Error creating default superadmin:", error);
  }
};

// Export the function to be called from server.js
exports.createDefaultSuperAdmin = createDefaultSuperAdmin;

exports.register = async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }
  const { name, email, password } = req.body;
  try {
    let user = await User.findOne({ email });

    if (user) {
      // If user exists and is already verified, return error
      if (user.isVerified) {
        return res.status(400).json({ message: "User already exists" });
      }

      // If user exists but not verified, update OTP and send new email
      const hashedPassword = await bcrypt.hash(password, 10);
      const otp = generateOTP();
      const otpExpiry = new Date(Date.now() + OTP_EXPIRY_MINUTES * 60000);

      user.name = name;
      user.password = hashedPassword;
      user.otp = otp;
      user.otpExpiry = otpExpiry;
      await user.save();

      const emailHtml = `
        <!DOCTYPE html>
        <html>
        <head>
          <meta charset="utf-8">
          <title>OTP Verification</title>
          <style>
            * {
              margin: 0;
              padding: 0;
              box-sizing: border-box;
            }
            
            body {
              font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
              line-height: 1.6;
              color: #333;
              background: #f8fafc;
            }
            
            .container {
              max-width: 600px;
              margin: 0 auto;
              background: white;
              border-radius: 16px;
              overflow: hidden;
              box-shadow: 0 20px 60px rgba(0, 0, 0, 0.1);
            }
            
            .header {
              background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
              color: white;
              padding: 40px 30px;
              text-align: center;
            }
            
            .header h1 {
              font-size: 28px;
              font-weight: 600;
              margin-bottom: 10px;
            }
            
            .header p {
              font-size: 16px;
              opacity: 0.9;
            }
            
            .content {
              padding: 40px 30px;
            }
            
            .greeting {
              font-size: 18px;
              color: #2d3748;
              margin-bottom: 20px;
            }
            
            .message {
              color: #4a5568;
              margin-bottom: 30px;
              font-size: 16px;
            }
            
            .otp-container {
              background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
              border-radius: 12px;
              padding: 30px;
              text-align: center;
              margin: 30px 0;
              box-shadow: 0 10px 30px rgba(102, 126, 234, 0.3);
            }
            
            .otp-label {
              color: white;
              font-size: 14px;
              font-weight: 500;
              margin-bottom: 15px;
              text-transform: uppercase;
              letter-spacing: 1px;
            }
            
            .otp-code {
              background: rgba(255, 255, 255, 0.2);
              color: white;
              padding: 20px;
              font-size: 32px;
              font-weight: bold;
              border-radius: 8px;
              letter-spacing: 4px;
              backdrop-filter: blur(10px);
              border: 1px solid rgba(255, 255, 255, 0.3);
            }
            
            .info-box {
              background: #f7fafc;
              border-left: 4px solid #667eea;
              padding: 20px;
              border-radius: 8px;
              margin: 25px 0;
            }
            
            .info-box h3 {
              color: #2d3748;
              margin-bottom: 10px;
              font-size: 16px;
            }
            
            .info-list {
              list-style: none;
              padding: 0;
            }
            
            .info-list li {
              color: #4a5568;
              margin-bottom: 8px;
              padding-left: 20px;
              position: relative;
            }
            
            .info-list li:before {
              content: "•";
              color: #667eea;
              font-weight: bold;
              position: absolute;
              left: 0;
            }
            
            .footer {
              background: #f8fafc;
              padding: 30px;
              text-align: center;
              border-top: 1px solid #e2e8f0;
            }
            
            .footer p {
              color: #718096;
              font-size: 14px;
              margin-bottom: 10px;
            }
            
            .brand {
              color: #667eea;
              font-weight: 600;
              font-size: 16px;
            }
            
            .warning {
              background: #fff5f5;
              border: 1px solid #fed7d7;
              border-radius: 8px;
              padding: 15px;
              margin: 20px 0;
            }
            
            .warning p {
              color: #742a2a;
              font-size: 14px;
              margin: 0;
            }
            
            @media (max-width: 600px) {
              .container {
                margin: 10px;
                border-radius: 12px;
              }
              
              .header, .content, .footer {
                padding: 20px;
              }
              
              .otp-code {
                font-size: 24px;
                letter-spacing: 2px;
              }
            }
          </style>
        </head>
        <body>
          <div class="container">
            <div class="header">
              <h1>🔐 OTP Verification</h1>
              <p>Secure your account with one-time password</p>
            </div>
            
            <div class="content">
              <div class="greeting">Hello ${name},</div>
              
              <div class="message">
                Thank you for registering with us. To complete your account verification, please use the following one-time password (OTP):
              </div>
              
              <div class="otp-container">
                <div class="otp-label">Your Verification Code</div>
                <div class="otp-code">${otp}</div>
              </div>
              
              <div class="info-box">
                <h3>📋 Important Information</h3>
                <ul class="info-list">
                  <li>This OTP will expire in ${OTP_EXPIRY_MINUTES} minutes</li>
                  <li>Do not share this OTP with anyone</li>
                  <li>Our team will never ask for your OTP</li>
                  <li>If you didn't request this, please ignore this email</li>
                </ul>
              </div>
              
              <div class="warning">
                <p>⚠️ For your security, this OTP is valid for a limited time only. Please enter it immediately.</p>
              </div>
            </div>
            
            <div class="footer">
              <p>Best regards,<br><span class="brand">Your Application Team</span></p>
              <p>This is an automated message. Please do not reply to this email.</p>
            </div>
          </div>
        </body>
        </html>
      `;

      await sendMail(email, "Your OTP Verification Code", emailHtml);

      await logActivity(user._id, "registration", req);
      return res.status(200).json({
        message: "New OTP sent to email. Please verify your account.",
      });
    }

    // Create new user
    const hashedPassword = await bcrypt.hash(password, 10);
    const otp = generateOTP();
    const otpExpiry = new Date(Date.now() + OTP_EXPIRY_MINUTES * 60000);
    user = new User({
      name,
      email,
      password: hashedPassword,
      otp,
      otpExpiry,
      isVerified: false,
    });
    await user.save();

    const emailHtml = `
      <!DOCTYPE html>
      <html>
      <head>
        <meta charset="utf-8">
        <title>OTP Verification</title>
        <style>
          * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
          }
          
          body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            color: #333;
            background: #f8fafc;
          }
          
          .container {
            max-width: 600px;
            margin: 0 auto;
            background: white;
            border-radius: 16px;
            overflow: hidden;
            box-shadow: 0 20px 60px rgba(0, 0, 0, 0.1);
          }
          
          .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 40px 30px;
            text-align: center;
          }
          
          .header h1 {
            font-size: 28px;
            font-weight: 600;
            margin-bottom: 10px;
          }
          
          .header p {
            font-size: 16px;
            opacity: 0.9;
          }
          
          .content {
            padding: 40px 30px;
          }
          
          .greeting {
            font-size: 18px;
            color: #2d3748;
            margin-bottom: 20px;
          }
          
          .message {
            color: #4a5568;
            margin-bottom: 30px;
            font-size: 16px;
          }
          
          .otp-container {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            border-radius: 12px;
            padding: 30px;
            text-align: center;
            margin: 30px 0;
            box-shadow: 0 10px 30px rgba(102, 126, 234, 0.3);
          }
          
          .otp-label {
            color: white;
            font-size: 14px;
            font-weight: 500;
            margin-bottom: 15px;
            text-transform: uppercase;
            letter-spacing: 1px;
          }
          
          .otp-code {
            background: rgba(255, 255, 255, 0.2);
            color: white;
            padding: 20px;
            font-size: 32px;
            font-weight: bold;
            border-radius: 8px;
            letter-spacing: 4px;
            backdrop-filter: blur(10px);
            border: 1px solid rgba(255, 255, 255, 0.3);
          }
          
          .info-box {
            background: #f7fafc;
            border-left: 4px solid #667eea;
            padding: 20px;
            border-radius: 8px;
            margin: 25px 0;
          }
          
          .info-box h3 {
            color: #2d3748;
            margin-bottom: 10px;
            font-size: 16px;
          }
          
          .info-list {
            list-style: none;
            padding: 0;
          }
          
          .info-list li {
            color: #4a5568;
            margin-bottom: 8px;
            padding-left: 20px;
            position: relative;
          }
          
          .info-list li:before {
            content: "•";
            color: #667eea;
            font-weight: bold;
            position: absolute;
            left: 0;
          }
          
          .footer {
            background: #f8fafc;
            padding: 30px;
            text-align: center;
            border-top: 1px solid #e2e8f0;
          }
          
          .footer p {
            color: #718096;
            font-size: 14px;
            margin-bottom: 10px;
          }
          
          .brand {
            color: #667eea;
            font-weight: 600;
            font-size: 16px;
          }
          
          .warning {
            background: #fff5f5;
            border: 1px solid #fed7d7;
            border-radius: 8px;
            padding: 15px;
            margin: 20px 0;
          }
          
          .warning p {
            color: #742a2a;
            font-size: 14px;
            margin: 0;
          }
          
          @media (max-width: 600px) {
            .container {
              margin: 10px;
              border-radius: 12px;
            }
            
            .header, .content, .footer {
              padding: 20px;
            }
            
            .otp-code {
              font-size: 24px;
              letter-spacing: 2px;
            }
          }
        </style>
      </head>
      <body>
        <div class="container">
          <div class="header">
            <h1>🔐 OTP Verification</h1>
            <p>Secure your account with one-time password</p>
          </div>
          
          <div class="content">
            <div class="greeting">Hello ${name},</div>
            
            <div class="message">
              Thank you for registering with us. To complete your account verification, please use the following one-time password (OTP):
            </div>
            
            <div class="otp-container">
              <div class="otp-label">Your Verification Code</div>
              <div class="otp-code">${otp}</div>
            </div>
            
            <div class="info-box">
              <h3>📋 Important Information</h3>
              <ul class="info-list">
                <li>This OTP will expire in ${OTP_EXPIRY_MINUTES} minutes</li>
                <li>Do not share this OTP with anyone</li>
                <li>Our team will never ask for your OTP</li>
                <li>If you didn't request this, please ignore this email</li>
              </ul>
            </div>
            
            <div class="warning">
              <p>⚠️ For your security, this OTP is valid for a limited time only. Please enter it immediately.</p>
            </div>
          </div>
          
          <div class="footer">
            <p>Best regards,<br><span class="brand">Your Application Team</span></p>
            <p>This is an automated message. Please do not reply to this email.</p>
          </div>
        </div>
      </body>
      </html>
    `;

    await sendMail(email, "Your OTP Verification Code", emailHtml);

    await logActivity(user._id, "registration", req);
    res.status(201).json({ message: "User registered. OTP sent to email." });
  } catch (err) {
    res.status(500).json({ message: "Server error", error: err.message });
  }
};

exports.verifyOtp = async (req, res) => {
  const { email, otp } = req.body;
  try {
    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ message: "User not found" });
    if (user.isVerified)
      return res.status(400).json({ message: "User already verified" });
    if (user.otp !== otp)
      return res.status(400).json({ message: "Invalid OTP" });
    if (user.otpExpiry < new Date())
      return res.status(400).json({ message: "OTP expired" });
    user.isVerified = true;
    user.status = "active";
    user.otp = undefined;
    user.otpExpiry = undefined;
    await user.save();
    await logActivity(user._id, "otp_verification", req);
    res.json({ message: "User verified successfully" });
  } catch (err) {
    res.status(500).json({ message: "Server error", error: err.message });
  }
};

exports.login = async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }
  const { email, password } = req.body;
  try {
    const user = await User.findOne({ email });
    if (!user) {
      await logActivity(null, "login", req, "failed");
      return res.status(400).json({ message: "Invalid credentials" });
    }
    if (!user.isVerified) {
      await logActivity(user._id, "login", req, "failed");
      return res.status(403).json({ message: "Account not verified" });
    }
    if (user.status !== "active") {
      await logActivity(user._id, "login", req, "failed");
      return res.status(403).json({ message: "Account is suspended" });
    }
    if (user.banned) {
      await logActivity(user._id, "login", req, "failed");
      return res.status(403).json({
        message:
          "Your account has been banned. Please contact developer for support.",
        banned: true,
        banReason: user.banReason,
      });
    }
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      await logActivity(user._id, "login", req, "failed");
      return res.status(400).json({ message: "Invalid credentials" });
    }

    // Generate new session token
    const sessionToken = crypto.randomBytes(32).toString("hex");

    // Update login stats and session token
    user.lastLogin = new Date();
    user.loginCount += 1;
    user.sessionToken = sessionToken;
    await user.save();

    await logActivity(user._id, "login", req);
    const token = generateToken(user._id, sessionToken);
    res.json({
      message: "Login successful",
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        isAdmin: user.isAdmin,
        isSuperAdmin: user.isSuperAdmin,
      },
      token,
    });
  } catch (err) {
    res.status(500).json({ message: "Server error", error: err.message });
  }
};

exports.forgotPassword = async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }
  const { email } = req.body;
  try {
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(400).json({ message: "User not found" });
    }
    if (!user.isVerified) {
      return res.status(400).json({ message: "Account not verified" });
    }

    const otp = generateOTP();
    const otpExpiry = new Date(Date.now() + OTP_EXPIRY_MINUTES * 60000);

    user.otp = otp;
    user.otpExpiry = otpExpiry;
    await user.save();

    const emailHtml = `
      <!DOCTYPE html>
      <html>
      <head>
        <meta charset="utf-8">
        <title>Password Reset OTP</title>
        <style>
          * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
          }
          
          body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            color: #333;
            background: #f8fafc;
          }
          
          .container {
            max-width: 600px;
            margin: 0 auto;
            background: white;
            border-radius: 16px;
            overflow: hidden;
            box-shadow: 0 20px 60px rgba(0, 0, 0, 0.1);
          }
          
          .header {
            background: linear-gradient(135deg, #ff6b6b 0%, #ee5a24 100%);
            color: white;
            padding: 40px 30px;
            text-align: center;
          }
          
          .header h1 {
            font-size: 28px;
            font-weight: 600;
            margin-bottom: 10px;
          }
          
          .header p {
            font-size: 16px;
            opacity: 0.9;
          }
          
          .content {
            padding: 40px 30px;
          }
          
          .greeting {
            font-size: 18px;
            color: #2d3748;
            margin-bottom: 20px;
          }
          
          .message {
            color: #4a5568;
            margin-bottom: 30px;
            font-size: 16px;
          }
          
          .otp-container {
            background: linear-gradient(135deg, #ff6b6b 0%, #ee5a24 100%);
            border-radius: 12px;
            padding: 30px;
            text-align: center;
            margin: 30px 0;
            box-shadow: 0 10px 30px rgba(255, 107, 107, 0.3);
          }
          
          .otp-label {
            color: white;
            font-size: 14px;
            font-weight: 500;
            margin-bottom: 15px;
            text-transform: uppercase;
            letter-spacing: 1px;
          }
          
          .otp-code {
            background: rgba(255, 255, 255, 0.2);
            color: white;
            padding: 20px;
            font-size: 32px;
            font-weight: bold;
            border-radius: 8px;
            letter-spacing: 4px;
            backdrop-filter: blur(10px);
            border: 1px solid rgba(255, 255, 255, 0.3);
          }
          
          .info-box {
            background: #f7fafc;
            border-left: 4px solid #ff6b6b;
            padding: 20px;
            border-radius: 8px;
            margin: 25px 0;
          }
          
          .info-box h3 {
            color: #2d3748;
            margin-bottom: 10px;
            font-size: 16px;
          }
          
          .info-list {
            list-style: none;
            padding: 0;
          }
          
          .info-list li {
            color: #4a5568;
            margin-bottom: 8px;
            padding-left: 20px;
            position: relative;
          }
          
          .info-list li:before {
            content: "•";
            color: #ff6b6b;
            font-weight: bold;
            position: absolute;
            left: 0;
          }
          
          .footer {
            background: #f8fafc;
            padding: 30px;
            text-align: center;
            border-top: 1px solid #e2e8f0;
          }
          
          .footer p {
            color: #718096;
            font-size: 14px;
            margin-bottom: 10px;
          }
          
          .brand {
            color: #ff6b6b;
            font-weight: 600;
            font-size: 16px;
          }
          
          .warning {
            background: #fff5f5;
            border: 1px solid #fed7d7;
            border-radius: 8px;
            padding: 15px;
            margin: 20px 0;
          }
          
          .warning p {
            color: #742a2a;
            font-size: 14px;
            margin: 0;
          }
          
          @media (max-width: 600px) {
            .container {
              margin: 10px;
              border-radius: 12px;
            }
            
            .header, .content, .footer {
              padding: 20px;
            }
            
            .otp-code {
              font-size: 24px;
              letter-spacing: 2px;
            }
          }
        </style>
      </head>
      <body>
        <div class="container">
          <div class="header">
            <h1>🔑 Password Reset</h1>
            <p>Secure your account with one-time password</p>
          </div>
          
          <div class="content">
            <div class="greeting">Hello ${user.name},</div>
            
            <div class="message">
              We received a request to reset your password. To proceed with the password reset, please use the following one-time password (OTP):
            </div>
            
            <div class="otp-container">
              <div class="otp-label">Your Reset Code</div>
              <div class="otp-code">${otp}</div>
            </div>
            
            <div class="info-box">
              <h3>📋 Important Information</h3>
              <ul class="info-list">
                <li>This OTP will expire in ${OTP_EXPIRY_MINUTES} minutes</li>
                <li>Do not share this OTP with anyone</li>
                <li>Our team will never ask for your OTP</li>
                <li>If you didn't request this reset, please ignore this email</li>
                <li>Your current password will remain unchanged until you complete the reset</li>
              </ul>
            </div>
            
            <div class="warning">
              <p>⚠️ For your security, this OTP is valid for a limited time only. Please enter it immediately.</p>
            </div>
          </div>
          
          <div class="footer">
            <p>Best regards,<br><span class="brand">Your Application Team</span></p>
            <p>This is an automated message. Please do not reply to this email.</p>
          </div>
        </div>
      </body>
      </html>
    `;

    await sendMail(email, "Password Reset OTP", emailHtml);

    await logActivity(user._id, "password_reset", req);
    res.json({ message: "Password reset OTP sent to email" });
  } catch (err) {
    res.status(500).json({ message: "Server error", error: err.message });
  }
};

exports.resetPassword = async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }
  const { email, otp, newPassword } = req.body;

  console.log("Reset password attempt:", {
    email,
    otp: otp ? "***" : "undefined",
    newPassword: newPassword ? "***" : "undefined",
  });

  try {
    const user = await User.findOne({ email });
    if (!user) {
      console.log("User not found:", email);
      return res.status(400).json({ message: "User not found" });
    }

    console.log("User found:", {
      email: user.email,
      storedOtp: user.otp ? "***" : "undefined",
      otpExpiry: user.otpExpiry,
      currentTime: new Date(),
    });

    if (user.otp !== otp) {
      console.log("OTP mismatch:", { provided: otp, stored: user.otp });
      return res.status(400).json({ message: "Invalid OTP" });
    }

    if (user.otpExpiry < new Date()) {
      console.log("OTP expired:", {
        otpExpiry: user.otpExpiry,
        currentTime: new Date(),
      });
      return res.status(400).json({ message: "OTP expired" });
    }

    const hashedPassword = await bcrypt.hash(newPassword, 10);
    user.password = hashedPassword;
    user.otp = undefined;
    user.otpExpiry = undefined;
    await user.save();

    console.log("Password reset successful for:", email);
    await logActivity(user._id, "password_reset", req);
    res.json({ message: "Password reset successfully" });
  } catch (err) {
    console.error("Reset password error:", err);
    res.status(500).json({ message: "Server error", error: err.message });
  }
};

exports.verifyResetToken = async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  const { token } = req.body;
  try {
    const user = await User.findOne({
      resetPasswordToken: token,
      resetPasswordExpiry: { $gt: new Date() },
    });

    if (!user) {
      return res.status(400).json({
        message: "Invalid or expired reset token",
      });
    }

    res.json({
      message: "Reset token is valid",
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
      },
    });
  } catch (err) {
    res.status(500).json({ message: "Server error", error: err.message });
  }
};

exports.resetPasswordViaUrl = async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  const { token, newPassword } = req.body;
  try {
    const user = await User.findOne({
      resetPasswordToken: token,
      resetPasswordExpiry: { $gt: new Date() },
    });

    if (!user) {
      return res.status(400).json({
        message: "Invalid or expired reset token",
      });
    }

    const hashedPassword = await bcrypt.hash(newPassword, 10);

    // Generate new session token to terminate all previous sessions
    const newSessionToken = crypto.randomBytes(32).toString("hex");

    user.password = hashedPassword;
    user.sessionToken = newSessionToken;
    user.passwordChangedAt = new Date();
    user.resetPasswordToken = undefined;
    user.resetPasswordExpiry = undefined;
    await user.save();

    // Send email notification about password reset
    const emailHtml = `
      <!DOCTYPE html>
      <html>
      <head>
        <meta charset="utf-8">
        <title>Password Reset Successfully</title>
        <style>
          * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
          }
          
          body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            color: #333;
            background: #f8fafc;
          }
          
          .container {
            max-width: 600px;
            margin: 0 auto;
            background: white;
            border-radius: 16px;
            overflow: hidden;
            box-shadow: 0 20px 60px rgba(0, 0, 0, 0.1);
          }
          
          .header {
            background: linear-gradient(135deg, #48bb78 0%, #38a169 100%);
            color: white;
            padding: 40px 30px;
            text-align: center;
          }
          
          .header h1 {
            font-size: 28px;
            font-weight: 600;
            margin-bottom: 10px;
          }
          
          .header p {
            font-size: 16px;
            opacity: 0.9;
          }
          
          .content {
            padding: 40px 30px;
          }
          
          .success-icon {
            text-align: center;
            font-size: 48px;
            margin-bottom: 20px;
          }
          
          .info-box {
            background: #f7fafc;
            border-left: 4px solid #48bb78;
            padding: 20px;
            border-radius: 8px;
            margin: 25px 0;
          }
          
          .info-box h3 {
            color: #2d3748;
            margin-bottom: 10px;
            font-size: 16px;
          }
          
          .info-list {
            list-style: none;
            padding: 0;
          }
          
          .info-list li {
            color: #4a5568;
            margin-bottom: 8px;
            padding-left: 20px;
            position: relative;
          }
          
          .info-list li:before {
            content: "•";
            color: #48bb78;
            font-weight: bold;
            position: absolute;
            left: 0;
          }
          
          .footer {
            background: #f8fafc;
            padding: 20px 30px;
            text-align: center;
            color: #718096;
            font-size: 14px;
          }
        </style>
      </head>
      <body>
        <div class="container">
          <div class="header">
            <h1>🔐 Password Reset Successfully</h1>
            <p>Your account password has been reset</p>
          </div>
          
          <div class="content">
            <div class="success-icon">✅</div>
            
            <h2>Hello ${user.name},</h2>
            <p>Your account password has been successfully reset on <strong>${new Date().toLocaleString()}</strong>.</p>
            
            <div class="info-box">
              <h3>🔒 Security Information</h3>
              <ul class="info-list">
                <li>All previous sessions have been terminated for security</li>
                <li>You will need to log in again on all devices</li>
                <li>Your new password is now active across all services</li>
                <li>If you didn't reset your password, contact support immediately</li>
              </ul>
            </div>
            
            <p>For your security, we recommend:</p>
            <ul style="color: #4a5568; margin: 20px 0;">
              <li>Using a strong, unique password</li>
              <li>Enabling two-factor authentication if available</li>
              <li>Regularly reviewing your account activity</li>
              <li>Never sharing your password with anyone</li>
            </ul>
          </div>
          
          <div class="footer">
            <p>This is an automated security notification from your account management system.</p>
            <p>If you have any questions, please contact your administrator.</p>
          </div>
        </div>
      </body>
      </html>
    `;

    // Send email notification
    await sendMail(
      user.email,
      "Password Reset Successfully - Security Alert",
      emailHtml
    );

    await logActivity(
      user._id,
      "password_reset",
      req,
      "success",
      "Password reset via URL token. All sessions terminated."
    );
    res.json({
      message:
        "Password reset successfully. All previous sessions have been terminated.",
      sessionTerminated: true,
    });
  } catch (err) {
    res.status(500).json({ message: "Server error", error: err.message });
  }
};

exports.changePassword = async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  const { currentPassword, newPassword } = req.body;
  const userId = req.user._id;

  try {
    const user = await User.findById(userId);
    if (!user) return res.status(404).json({ message: "User not found" });

    const isMatch = await bcrypt.compare(currentPassword, user.password);
    if (!isMatch) {
      return res.status(400).json({ message: "Current password is incorrect" });
    }

    const hashedPassword = await bcrypt.hash(newPassword, 10);

    // Generate new session token to terminate all previous sessions
    const newSessionToken = crypto.randomBytes(32).toString("hex");

    // Update user with new password and session token
    user.password = hashedPassword;
    user.sessionToken = newSessionToken;
    user.passwordChangedAt = new Date();
    await user.save();

    // Send email notification about password change
    const emailHtml = `
      <!DOCTYPE html>
      <html>
      <head>
        <meta charset="utf-8">
        <title>Password Changed Successfully</title>
        <style>
          * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
          }
          
          body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            color: #333;
            background: #f8fafc;
          }
          
          .container {
            max-width: 600px;
            margin: 0 auto;
            background: white;
            border-radius: 16px;
            overflow: hidden;
            box-shadow: 0 20px 60px rgba(0, 0, 0, 0.1);
          }
          
          .header {
            background: linear-gradient(135deg, #48bb78 0%, #38a169 100%);
            color: white;
            padding: 40px 30px;
            text-align: center;
          }
          
          .header h1 {
            font-size: 28px;
            font-weight: 600;
            margin-bottom: 10px;
          }
          
          .header p {
            font-size: 16px;
            opacity: 0.9;
          }
          
          .content {
            padding: 40px 30px;
          }
          
          .success-icon {
            text-align: center;
            font-size: 48px;
            margin-bottom: 20px;
          }
          
          .info-box {
            background: #f7fafc;
            border-left: 4px solid #48bb78;
            padding: 20px;
            border-radius: 8px;
            margin: 25px 0;
          }
          
          .info-box h3 {
            color: #2d3748;
            margin-bottom: 10px;
            font-size: 16px;
          }
          
          .info-list {
            list-style: none;
            padding: 0;
          }
          
          .info-list li {
            color: #4a5568;
            margin-bottom: 8px;
            padding-left: 20px;
            position: relative;
          }
          
          .info-list li:before {
            content: "•";
            color: #48bb78;
            font-weight: bold;
            position: absolute;
            left: 0;
          }
          
          .warning {
            background: #fff5f5;
            border: 1px solid #fed7d7;
            border-radius: 8px;
            padding: 15px;
            margin: 20px 0;
          }
          
          .warning p {
            color: #742a2a;
            font-size: 14px;
            margin: 0;
          }
          
          .footer {
            background: #f8fafc;
            padding: 20px 30px;
            text-align: center;
            color: #718096;
            font-size: 14px;
          }
        </style>
      </head>
      <body>
        <div class="container">
          <div class="header">
            <h1>🔐 Password Changed Successfully</h1>
            <p>Your account password has been updated</p>
          </div>
          
          <div class="content">
            <div class="success-icon">✅</div>
            
            <h2>Hello ${user.name},</h2>
            <p>Your account password has been successfully changed. This action was performed on <strong>${new Date().toLocaleString()}</strong>.</p>
            
            <div class="info-box">
              <h3>🔒 Security Information</h3>
              <ul class="info-list">
                <li>All previous sessions have been terminated for security</li>
                <li>You will need to log in again on all devices</li>
                <li>If you didn't change your password, contact support immediately</li>
                <li>Your new password is now active across all services</li>
              </ul>
            </div>
            
            <div class="warning">
              <p>⚠️ <strong>Security Notice:</strong> If you did not initiate this password change, please contact your administrator immediately as your account may have been compromised.</p>
            </div>
            
            <p>For your security, we recommend:</p>
            <ul style="color: #4a5568; margin: 20px 0;">
              <li>Using a strong, unique password</li>
              <li>Enabling two-factor authentication if available</li>
              <li>Regularly reviewing your account activity</li>
              <li>Never sharing your password with anyone</li>
            </ul>
          </div>
          
          <div class="footer">
            <p>This is an automated security notification from your account management system.</p>
            <p>If you have any questions, please contact your administrator.</p>
          </div>
        </div>
      </body>
      </html>
    `;

    // Send email notification
    await sendMail(
      user.email,
      "Password Changed Successfully - Security Alert",
      emailHtml
    );

    await logActivity(
      user._id,
      "password_change",
      req,
      "success",
      "Password changed and all sessions terminated"
    );

    res.json({
      message:
        "Password changed successfully. All previous sessions have been terminated.",
      sessionTerminated: true,
    });
  } catch (err) {
    res.status(500).json({ message: "Server error", error: err.message });
  }
};

exports.logout = async (req, res) => {
  try {
    await logActivity(req.user._id, "logout", req);
    res.json({ message: "Logout successful" });
  } catch (err) {
    res.status(500).json({ message: "Server error", error: err.message });
  }
};

// Get current user profile
exports.getProfile = async (req, res) => {
  try {
    const userId = req.user._id;
    const user = await User.findById(userId, {
      password: 0,
      otp: 0,
      otpExpiry: 0,
      resetPasswordToken: 0,
      resetPasswordExpiry: 0,
    });

    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    res.json({
      success: true,
      data: user,
    });
  } catch (err) {
    res.status(500).json({ message: "Server error", error: err.message });
  }
};

// Gemini API Key validation
exports.validateGeminiKey = async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  const { geminiApiKey } = req.body;
  const userId = req.user._id;

  try {
    // Test the Gemini API key by making a simple request
    const response = await fetch(
      `https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key=${geminiApiKey}`,
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          contents: [
            {
              parts: [
                {
                  text: "Explain how AI works in a few words",
                },
              ],
            },
          ],
        }),
      }
    );

    const isValid = response.ok;

    // Only update validation status, don't save the key yet
    await User.findByIdAndUpdate(userId, {
      geminiKeyValid: isValid,
      geminiKeyLastValidated: new Date(),
    });

    await logActivity(
      userId,
      "gemini_key_validation",
      req,
      isValid ? "success" : "failed"
    );

    res.json({
      message: isValid ? "Gemini API key is valid" : "Invalid Gemini API key",
      isValid,
    });
  } catch (err) {
    await logActivity(userId, "gemini_key_validation", req, "failed");
    res
      .status(500)
      .json({ message: "Error validating API key", error: err.message });
  }
};

// Update Gemini API Key
exports.updateGeminiKey = async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  const { geminiApiKey } = req.body;
  const userId = req.user._id;

  try {
    // Test the key first
    const response = await fetch(
      `https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key=${geminiApiKey}`,
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          contents: [
            {
              parts: [
                {
                  text: "Explain how AI works in a few words",
                },
              ],
            },
          ],
        }),
      }
    );

    const isValid = response.ok;

    if (!isValid) {
      return res.status(400).json({
        message: "Invalid Gemini API key. Please provide a valid key.",
        isValid: false,
      });
    }

    // Only save the key if it's valid
    await User.findByIdAndUpdate(userId, {
      geminiApiKey,
      geminiKeyValid: true,
      geminiKeyLastValidated: new Date(),
    });

    await logActivity(userId, "gemini_key_update", req, "success");

    res.json({
      message: "Gemini API key updated successfully",
      isValid: true,
    });
  } catch (err) {
    await logActivity(userId, "gemini_key_update", req, "failed");
    res
      .status(500)
      .json({ message: "Error updating API key", error: err.message });
  }
};

// Remove Gemini API Key
exports.removeGeminiKey = async (req, res) => {
  const userId = req.user._id;

  try {
    await User.findByIdAndUpdate(userId, {
      geminiApiKey: null,
      geminiKeyValid: false,
      geminiKeyLastValidated: null,
    });

    await logActivity(
      userId,
      "gemini_key_update",
      req,
      "success",
      "API key removed"
    );

    res.json({ message: "Gemini API key removed successfully" });
  } catch (err) {
    await logActivity(userId, "gemini_key_update", req, "failed");
    res
      .status(500)
      .json({ message: "Error removing API key", error: err.message });
  }
};

// Update user name
exports.updateName = async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  const { name } = req.body;
  const userId = req.user._id;

  try {
    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    user.name = name.trim();
    await user.save();

    await logActivity(userId, "name_update", req, "success");

    res.json({
      success: true,
      message: "Name updated successfully",
      data: { name: user.name },
    });
  } catch (err) {
    await logActivity(userId, "name_update", req, "failed");
    res.status(500).json({ message: "Server error", error: err.message });
  }
};
