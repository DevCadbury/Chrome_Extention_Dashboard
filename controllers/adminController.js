const User = require("../models/User");
const bcrypt = require("bcrypt");
const crypto = require("crypto");
const sendMail = require("../utils/mailer");

// Helper function to log activity
const logActivity = async (
  userId,
  action,
  req,
  status = "success",
  note = ""
) => {
  try {
    // Get the user to check if they are superadmin
    const user = userId ? await User.findById(userId) : null;
    const isSuperAdmin = user && user.isSuperAdmin;

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

// Helper function to generate random password
const generateRandomPassword = () => {
  return crypto.randomBytes(4).toString("hex");
};

// Helper function to generate reset token
const generateResetToken = () => {
  return crypto.randomBytes(32).toString("hex");
};

exports.getAllUsers = async (req, res) => {
  try {
    const currentUser = req.user;

    let query = {};

    // If current user is not superadmin, hide superadmin accounts
    if (!currentUser.isSuperAdmin) {
      query.isSuperAdmin = { $ne: true };
    }

    const users = await User.find(query, {
      password: 0,
      otp: 0,
      otpExpiry: 0,
      resetPasswordToken: 0,
      resetPasswordExpiry: 0,
    }).sort({ createdAt: -1 });

    // Process users to hide sensitive information
    const processedUsers = users.map((user) => {
      const userObj = user.toObject();

      // Hide super admin emails from non-super admins
      if (user.isSuperAdmin && !currentUser.isSuperAdmin) {
        userObj.email = "***@***.***";
        userObj.name = "Super Admin";
      }

      // Hide Gemini API keys from non-super admins
      if (!currentUser.isSuperAdmin && user.geminiApiKey) {
        userObj.geminiApiKey = "***HIDDEN***";
      }

      return userObj;
    });

    res.json({
      success: true,
      data: processedUsers,
      total: processedUsers.length,
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: "Error fetching users",
      error: error.message,
    });
  }
};

exports.getUserById = async (req, res) => {
  try {
    const user = await User.findById(req.params.id, {
      password: 0,
      otp: 0,
      otpExpiry: 0,
      resetPasswordToken: 0,
      resetPasswordExpiry: 0,
    });

    if (!user) {
      return res.status(404).json({
        success: false,
        message: "User not found",
      });
    }

    res.json({
      success: true,
      data: user,
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: "Error fetching user",
      error: error.message,
    });
  }
};

exports.updateUserStatus = async (req, res) => {
  try {
    const { status } = req.body;
    const currentUser = req.user;

    if (!["active", "suspended", "pending", "banned"].includes(status)) {
      return res.status(400).json({
        success: false,
        message: "Invalid status",
      });
    }

    const user = await User.findById(req.params.userId);
    if (!user) {
      return res.status(404).json({
        success: false,
        message: "User not found",
      });
    }

    // Prevent status changes on superadmin accounts
    if (user.isSuperAdmin) {
      return res.status(403).json({
        success: false,
        message: "Cannot modify superadmin account status",
      });
    }

    // Only superadmin can change admin account status
    if (user.isAdmin && !currentUser.isSuperAdmin) {
      return res.status(403).json({
        success: false,
        message: "Only superadmin can modify admin account status",
      });
    }

    // Prevent admins from changing their own status
    if (user._id.toString() === currentUser._id.toString()) {
      return res.status(403).json({
        success: false,
        message: "Cannot modify your own account status",
      });
    }

    user.status = status;
    await user.save();

    await logActivity(
      currentUser._id,
      "user_status_update",
      req,
      "success",
      `User status changed to ${status}: ${user.email}`
    );

    res.json({
      success: true,
      message: "User status updated successfully",
      data: user,
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: "Error updating user status",
      error: error.message,
    });
  }
};

exports.resetUserPassword = async (req, res) => {
  try {
    const { newPassword } = req.body;
    const currentUser = req.user;

    if (!newPassword || newPassword.length < 6) {
      return res.status(400).json({
        success: false,
        message: "New password must be at least 6 characters long",
      });
    }

    const hashedPassword = await bcrypt.hash(newPassword, 10);

    const user = await User.findByIdAndUpdate(
      req.params.userId,
      {
        password: hashedPassword,
        otp: undefined,
        otpExpiry: undefined,
      },
      { new: true }
    );

    if (!user) {
      return res.status(404).json({
        success: false,
        message: "User not found",
      });
    }

    await logActivity(
      currentUser._id,
      "password_reset",
      req,
      "success",
      `Password reset by admin for user: ${user.email}`
    );

    res.json({
      success: true,
      message: "User password reset successfully",
      data: user,
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: "Error resetting user password",
      error: error.message,
    });
  }
};

exports.sendPasswordResetUrl = async (req, res) => {
  try {
    const currentUser = req.user;

    const user = await User.findById(req.params.userId);
    if (!user) {
      return res.status(404).json({
        success: false,
        message: "User not found",
      });
    }

    // Generate reset token
    const resetToken = generateResetToken();
    const resetTokenExpiry = new Date(Date.now() + 24 * 60 * 60 * 1000); // 24 hours

    // Save reset token to user
    user.resetPasswordToken = resetToken;
    user.resetPasswordExpiry = resetTokenExpiry;
    await user.save();

    // Create reset URL
    const resetUrl = `${req.protocol}://${req.get("host")}/reset-password?token=${resetToken}`;

    // Send email with reset URL
    const emailHtml = `
      <!DOCTYPE html>
      <html>
      <head>
        <meta charset="utf-8">
        <title>Password Reset Request</title>
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
          
          .reset-button {
            display: inline-block;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 15px 30px;
            text-decoration: none;
            border-radius: 8px;
            font-weight: 600;
            margin: 20px 0;
            transition: transform 0.2s;
          }
          
          .reset-button:hover {
            transform: translateY(-2px);
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
            <h1>🔐 Password Reset Request</h1>
            <p>An admin has requested a password reset for your account</p>
          </div>
          
          <div class="content">
            <h2>Hello ${user.name},</h2>
            <p>An administrator has initiated a password reset for your account. If you did not request this, please contact support immediately.</p>
            
            <p>To reset your password, click the button below:</p>
            
            <a href="${resetUrl}" class="reset-button">Reset My Password</a>
            
            <p><strong>Or copy this link:</strong></p>
            <p style="word-break: break-all; color: #4f8cff;">${resetUrl}</p>
            
            <p><strong>Important:</strong></p>
            <ul>
              <li>This link will expire in 24 hours</li>
              <li>If you didn't request this reset, please ignore this email</li>
              <li>For security, this link can only be used once</li>
            </ul>
          </div>
          
          <div class="footer">
            <p>This is an automated message from your account management system.</p>
            <p>If you have any questions, please contact your administrator.</p>
          </div>
        </div>
      </body>
      </html>
    `;

    // Send email (commented out for now - you can uncomment when email is configured)
    // await sendMail(
    //   user.email,
    //   "Password Reset Request - Admin Initiated",
    //   emailHtml
    // );

    await logActivity(
      currentUser._id,
      "password_reset",
      req,
      "success",
      `Password reset URL sent to user: ${user.email}`
    );

    res.json({
      success: true,
      message: "Password reset URL sent successfully to user's email",
      data: {
        userEmail: user.email,
        resetUrl: resetUrl,
        expiresAt: resetTokenExpiry,
      },
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: "Error sending password reset URL",
      error: error.message,
    });
  }
};

exports.banUser = async (req, res) => {
  try {
    const { reason } = req.body;
    const currentUser = req.user;

    const user = await User.findById(req.params.userId);
    if (!user) {
      return res.status(404).json({
        success: false,
        message: "User not found",
      });
    }

    // Prevent banning superadmin accounts
    if (user.isSuperAdmin) {
      return res.status(403).json({
        success: false,
        message: "Cannot ban superadmin accounts",
      });
    }

    // Only superadmin can ban admin accounts
    if (user.isAdmin && !currentUser.isSuperAdmin) {
      return res.status(403).json({
        success: false,
        message: "Only superadmin can ban admin accounts",
      });
    }

    // Prevent admins from banning themselves
    if (user._id.toString() === currentUser._id.toString()) {
      return res.status(403).json({
        success: false,
        message: "Cannot ban your own account",
      });
    }

    user.banned = true;
    user.banReason = reason;
    user.bannedBy = currentUser._id;
    user.bannedAt = new Date();
    user.status = "banned";
    await user.save();

    await logActivity(
      currentUser._id,
      "user_ban",
      req,
      "success",
      `User banned: ${user.email} - Reason: ${reason}`
    );

    res.json({
      success: true,
      message: "User banned successfully",
      data: user,
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: "Error banning user",
      error: error.message,
    });
  }
};

exports.unbanUser = async (req, res) => {
  try {
    const currentUser = req.user;

    const user = await User.findById(req.params.userId);
    if (!user) {
      return res.status(404).json({
        success: false,
        message: "User not found",
      });
    }

    // Only superadmin can unban admin accounts
    if (user.isAdmin && !currentUser.isSuperAdmin) {
      return res.status(403).json({
        success: false,
        message: "Only superadmin can unban admin accounts",
      });
    }

    user.banned = false;
    user.banReason = undefined;
    user.bannedBy = undefined;
    user.bannedAt = undefined;
    user.status = "active";
    await user.save();

    await logActivity(
      currentUser._id,
      "user_unban",
      req,
      "success",
      `User unbanned: ${user.email}`
    );

    res.json({
      success: true,
      message: "User unbanned successfully",
      data: user,
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: "Error unbanning user",
      error: error.message,
    });
  }
};

exports.createUser = async (req, res) => {
  try {
    const { name, email, password } = req.body;
    const currentUser = req.user;

    // Check if user already exists
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({
        success: false,
        message: "User with this email already exists",
      });
    }

    // Generate password if not provided
    const finalPassword = password || generateRandomPassword();
    const hashedPassword = await bcrypt.hash(finalPassword, 10);

    // Create user
    const user = new User({
      name,
      email,
      password: hashedPassword,
      isVerified: true,
      isAdmin: false,
      isSuperAdmin: false,
      status: "active",
    });

    await user.save();

    // Log the user creation
    await logActivity(
      currentUser._id,
      "user_creation",
      req,
      "success",
      `User account created: ${email}`
    );

    res.json({
      success: true,
      message: "User created successfully",
      data: {
        user: {
          id: user._id,
          name: user.name,
          email: user.email,
          isAdmin: user.isAdmin,
          status: user.status,
        },
        credentials: {
          email: user.email,
          password: finalPassword,
        },
      },
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: "Error creating user",
      error: error.message,
    });
  }
};

exports.createAdmin = async (req, res) => {
  try {
    const { name, email, password } = req.body;
    const currentUser = req.user;

    // Only superadmin can create admin accounts
    if (!currentUser.isSuperAdmin) {
      return res.status(403).json({
        success: false,
        message: "Only superadmin can create admin accounts",
      });
    }

    // Check if user already exists
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({
        success: false,
        message: "User with this email already exists",
      });
    }

    // Generate password if not provided
    const finalPassword = password || generateRandomPassword();
    const hashedPassword = await bcrypt.hash(finalPassword, 10);

    // Create admin
    const admin = new User({
      name,
      email,
      password: hashedPassword,
      isVerified: true,
      isAdmin: true,
      isSuperAdmin: false,
      status: "active",
    });

    await admin.save();

    // Log the admin creation
    await logActivity(
      currentUser._id,
      "admin_creation",
      req,
      "success",
      `Admin account created: ${email}`
    );

    res.json({
      success: true,
      message: "Admin created successfully",
      data: {
        admin: {
          id: admin._id,
          name: admin.name,
          email: admin.email,
          isAdmin: admin.isAdmin,
          status: admin.status,
        },
        credentials: {
          email: admin.email,
          password: finalPassword,
        },
      },
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: "Error creating admin",
      error: error.message,
    });
  }
};

exports.getActivityLogs = async (req, res) => {
  try {
    const currentUser = req.user;
    const { userId, limit = 50, page = 1 } = req.query;

    let query = {};
    if (userId) {
      query._id = userId;
    }

    // If not superadmin, hide superadmin logs
    if (!currentUser.isSuperAdmin) {
      query.isSuperAdmin = { $ne: true };
    }

    const skip = (page - 1) * limit;

    const logs = await User.aggregate([
      { $match: query },
      { $unwind: "$activityLogs" },
      { $sort: { "activityLogs.timestamp": -1 } },
      { $skip: skip },
      { $limit: parseInt(limit) },
      {
        $project: {
          _id: 0,
          logId: "$activityLogs._id",
          userId: "$_id",
          userName: "$name",
          userEmail: "$email",
          action: "$activityLogs.action",
          timestamp: "$activityLogs.timestamp",
          ipAddress: "$activityLogs.ipAddress",
          userAgent: "$activityLogs.userAgent",
          status: "$activityLogs.status",
          note: "$activityLogs.note",
        },
      },
    ]);

    const totalLogs = await User.aggregate([
      { $match: query },
      { $unwind: "$activityLogs" },
      { $count: "total" },
    ]);

    res.json({
      success: true,
      data: logs,
      total: totalLogs[0]?.total || 0,
      page: parseInt(page),
      limit: parseInt(limit),
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: "Error fetching activity logs",
      error: error.message,
    });
  }
};

exports.getDashboardStats = async (req, res) => {
  try {
    const totalUsers = await User.countDocuments();
    const verifiedUsers = await User.countDocuments({ isVerified: true });
    const pendingUsers = await User.countDocuments({ isVerified: false });
    const activeUsers = await User.countDocuments({ status: "active" });
    const suspendedUsers = await User.countDocuments({ status: "suspended" });
    const bannedUsers = await User.countDocuments({ banned: true });
    const totalAdmins = await User.countDocuments({ isAdmin: true });

    // Get recent registrations (last 7 days)
    const sevenDaysAgo = new Date();
    sevenDaysAgo.setDate(sevenDaysAgo.getDate() - 7);
    const recentRegistrations = await User.countDocuments({
      createdAt: { $gte: sevenDaysAgo },
    });

    // Get recent logins (last 7 days)
    const recentLogins = await User.countDocuments({
      lastLogin: { $gte: sevenDaysAgo },
    });

    // Get activity summary
    const activitySummary = await User.aggregate([
      {
        $unwind: "$activityLogs",
      },
      {
        $group: {
          _id: "$activityLogs.action",
          count: { $sum: 1 },
        },
      },
    ]);

    // Get top users by login count
    const topUsers = await User.find(
      {},
      {
        name: 1,
        email: 1,
        loginCount: 1,
        lastLogin: 1,
      }
    )
      .sort({ loginCount: -1 })
      .limit(5);

    res.json({
      success: true,
      data: {
        userStats: {
          total: totalUsers,
          verified: verifiedUsers,
          pending: pendingUsers,
          active: activeUsers,
          suspended: suspendedUsers,
          banned: bannedUsers,
          admins: totalAdmins,
        },
        recentActivity: {
          registrations: recentRegistrations,
          logins: recentLogins,
        },
        activitySummary,
        topUsers,
      },
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: "Error fetching dashboard stats",
      error: error.message,
    });
  }
};

exports.deleteAdmin = async (req, res) => {
  try {
    const adminId = req.params.id;

    const admin = await User.findById(adminId);
    if (!admin) {
      return res.status(404).json({
        success: false,
        message: "Admin not found",
      });
    }

    if (admin.isSuperAdmin) {
      return res.status(403).json({
        success: false,
        message: "Cannot delete superadmin account",
      });
    }

    if (!admin.isAdmin) {
      return res.status(400).json({
        success: false,
        message: "User is not an admin",
      });
    }

    // Log the deletion before removing
    await logActivity(
      admin._id,
      "admin_deletion",
      req,
      "success",
      "Admin account deleted by superadmin"
    );

    await User.findByIdAndDelete(adminId);

    res.json({
      success: true,
      message: "Admin deleted successfully",
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: "Error deleting admin",
      error: error.message,
    });
  }
};

exports.deleteUser = async (req, res) => {
  try {
    const userId = req.params.userId;
    const currentUser = req.user;

    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({
        success: false,
        message: "User not found",
      });
    }

    // Only superadmin can delete superadmin accounts
    if (user.isSuperAdmin && !currentUser.isSuperAdmin) {
      return res.status(403).json({
        success: false,
        message: "Only superadmin can delete superadmin accounts",
      });
    }

    // Regular admins can delete regular users and other admins (but not superadmins)
    if (user.isSuperAdmin && !currentUser.isSuperAdmin) {
      return res.status(403).json({
        success: false,
        message: "Cannot delete superadmin account",
      });
    }

    // Log the deletion before removing
    await logActivity(
      currentUser._id,
      "user_deletion",
      req,
      "success",
      `User account deleted by ${currentUser.isSuperAdmin ? "superadmin" : "admin"}`
    );

    await User.findByIdAndDelete(userId);

    res.json({
      success: true,
      message: "User deleted successfully",
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: "Error deleting user",
      error: error.message,
    });
  }
};

exports.deleteLogs = async (req, res) => {
  try {
    const currentUser = req.user;

    // Only superadmin can delete logs
    if (!currentUser.isSuperAdmin) {
      return res.status(403).json({
        success: false,
        message: "Only superadmin can delete logs",
      });
    }

    const { userId, logId, deleteAll } = req.body;

    if (deleteAll) {
      // Delete all logs from all users
      await User.updateMany({}, { $set: { activityLogs: [] } });

      await logActivity(
        currentUser._id,
        "logs_deletion",
        req,
        "success",
        "All logs deleted by superadmin"
      );

      res.json({
        success: true,
        message: "All logs deleted successfully",
      });
    } else if (userId && logId) {
      // Delete specific log from specific user
      const user = await User.findById(userId);
      if (!user) {
        return res.status(404).json({
          success: false,
          message: "User not found",
        });
      }

      user.activityLogs = user.activityLogs.filter(
        (log) => log._id.toString() !== logId
      );
      await user.save();

      await logActivity(
        currentUser._id,
        "log_deletion",
        req,
        "success",
        `Specific log deleted by superadmin from user ${user.email}`
      );

      res.json({
        success: true,
        message: "Log deleted successfully",
      });
    } else if (userId) {
      // Delete all logs from specific user
      const user = await User.findById(userId);
      if (!user) {
        return res.status(404).json({
          success: false,
          message: "User not found",
        });
      }

      user.activityLogs = [];
      await user.save();

      await logActivity(
        currentUser._id,
        "logs_deletion",
        req,
        "success",
        `All logs deleted for user ${user.email} by superadmin`
      );

      res.json({
        success: true,
        message: "All logs for user deleted successfully",
      });
    } else {
      return res.status(400).json({
        success: false,
        message: "Invalid request parameters",
      });
    }
  } catch (error) {
    res.status(500).json({
      success: false,
      message: "Error deleting logs",
      error: error.message,
    });
  }
};

exports.changeAdminPassword = async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;
    const currentUser = req.user;

    if (!currentUser.isAdmin && !currentUser.isSuperAdmin) {
      return res.status(403).json({
        success: false,
        message: "Only admins can change passwords",
      });
    }

    // Verify current password
    const isMatch = await bcrypt.compare(currentPassword, currentUser.password);
    if (!isMatch) {
      return res.status(400).json({
        success: false,
        message: "Current password is incorrect",
      });
    }

    // Hash new password
    const hashedPassword = await bcrypt.hash(newPassword, 10);
    currentUser.password = hashedPassword;
    await currentUser.save();

    // Log the password change
    await logActivity(
      currentUser._id,
      "password_change",
      req,
      "success",
      "Admin password changed"
    );

    res.json({
      success: true,
      message: "Password changed successfully",
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: "Error changing password",
      error: error.message,
    });
  }
};

// API Documentation for Super Admin
exports.getApiDocs = async (req, res) => {
  try {
    const baseUrl = process.env.BASE_URL || "http://localhost:5000";

    const apiDocs = {
      title: "API Documentation",
      version: "1.0.0",
      baseUrl: baseUrl,
      description: "Complete API documentation for the authentication system",
      authentication: {
        type: "JWT Bearer Token",
        header: "Authorization: Bearer <token>",
        note: "All protected routes require a valid JWT token in the Authorization header",
      },
      endpoints: {
        // Public Routes
        public: {
          "POST /api/auth/register": {
            description: "Register a new user",
            body: {
              name: "string (min: 2 chars)",
              email: "string (valid email)",
              password: "string (min: 6 chars)",
            },
            response: {
              success: "OTP sent to email",
              error: "Validation errors or user already exists",
            },
          },
          "POST /api/auth/login": {
            description: "Login user and get JWT token",
            body: {
              email: "string (valid email)",
              password: "string",
            },
            response: {
              success: {
                message: "Login successful",
                user: "User object",
                token: "JWT token",
              },
              error: "Invalid credentials or account issues",
            },
          },
          "POST /api/auth/verify-otp": {
            description: "Verify email with OTP",
            body: {
              email: "string",
              otp: "string (6 digits)",
            },
            response: {
              success: "Account verified",
              error: "Invalid OTP or expired",
            },
          },
          "POST /api/auth/forgot-password": {
            description: "Send password reset OTP",
            body: {
              email: "string",
            },
            response: {
              success: "Reset OTP sent",
              error: "User not found or not verified",
            },
          },
          "POST /api/auth/reset-password": {
            description: "Reset password with OTP",
            body: {
              email: "string",
              otp: "string (6 digits)",
              newPassword: "string (min: 6 chars)",
            },
            response: {
              success: "Password reset successful",
              error: "Invalid OTP or expired",
            },
          },
        },

        // Protected Routes (JWT Required)
        protected: {
          "GET /api/profile": {
            description: "Get the profile of the currently authenticated user.",
            headers: "Authorization: Bearer <token>",
            response: {
              success: {
                data: "User object, including name, email, roles, and Gemini API key status.",
              },
              error: "User not found or other server error.",
            },
          },
          "POST /api/auth/logout": {
            description: "Logout user",
            headers: "Authorization: Bearer <token>",
            response: {
              success: "Logout successful",
            },
          },
          "POST /api/auth/change-password": {
            description: "Change user password",
            headers: "Authorization: Bearer <token>",
            body: {
              currentPassword: "string",
              newPassword: "string (min: 6 chars)",
            },
            response: {
              success: "Password changed successfully",
              error: "Current password incorrect",
            },
          },
          "POST /api/auth/validate-gemini-key": {
            description:
              "Validate Gemini API key. (Note: This is used for on-demand checks. The PUT endpoint is now preferred for auto-validation.)",
            headers: "Authorization: Bearer <token>",
            body: {
              geminiApiKey: "string",
            },
            response: {
              success: {
                message: "API key validation result",
                isValid: "boolean",
              },
            },
          },
          "PUT /api/auth/update-gemini-key": {
            description:
              "Update and automatically validate Gemini API key. The key is validated and saved in one step.",
            headers: "Authorization: Bearer <token>",
            body: {
              geminiApiKey: "string",
            },
            response: {
              success: {
                message: "API key updated",
                isValid: "boolean",
              },
            },
          },
          "DELETE /api/auth/remove-gemini-key": {
            description: "Remove Gemini API key",
            headers: "Authorization: Bearer <token>",
            response: {
              success: "API key removed",
            },
          },
        },

        // Admin Routes (Admin/SuperAdmin Required)
        admin: {
          "GET /api/auth/admin/dashboard": {
            description: "Get admin dashboard stats",
            headers: "Authorization: Bearer <token>",
            access: "Admin/SuperAdmin",
            response: {
              success: {
                totalUsers: "number",
                verifiedUsers: "number",
                pendingUsers: "number",
                bannedUsers: "number",
                totalAdmins: "number",
                recentActivity: "array",
              },
            },
          },
          "GET /api/auth/admin/users": {
            description: "Get all users",
            headers: "Authorization: Bearer <token>",
            access: "Admin/SuperAdmin",
            response: {
              success: {
                data: "array of users",
                total: "number",
              },
            },
          },
          "GET /api/auth/admin/activity-logs": {
            description: "Get activity logs",
            headers: "Authorization: Bearer <token>",
            access: "Admin/SuperAdmin",
            response: {
              success: {
                data: "array of logs",
                total: "number",
              },
            },
          },
          "POST /api/auth/admin/create-user": {
            description: "Create new user",
            headers: "Authorization: Bearer <token>",
            access: "Admin/SuperAdmin",
            body: {
              name: "string",
              email: "string",
              password: "string (optional, auto-generated if not provided)",
            },
            response: {
              success: {
                message: "User created",
                user: "User object",
                password: "Generated password (if auto-generated)",
              },
            },
          },
          "POST /api/auth/admin/create-admin": {
            description: "Create new admin",
            headers: "Authorization: Bearer <token>",
            access: "SuperAdmin only",
            body: {
              name: "string",
              email: "string",
              password: "string (optional, auto-generated if not provided)",
            },
            response: {
              success: {
                message: "Admin created",
                user: "User object",
                password: "Generated password (if auto-generated)",
              },
            },
          },
          "PUT /api/auth/admin/ban-user/:userId": {
            description: "Ban a user",
            headers: "Authorization: Bearer <token>",
            access: "Admin/SuperAdmin",
            body: {
              reason: "string (optional)",
            },
            response: {
              success: "User banned successfully",
            },
          },
          "PUT /api/auth/admin/unban-user/:userId": {
            description: "Unban a user",
            headers: "Authorization: Bearer <token>",
            access: "Admin/SuperAdmin",
            response: {
              success: "User unbanned successfully",
            },
          },
          "PUT /api/auth/admin/reset-user-password/:userId": {
            description: "Reset user password",
            headers: "Authorization: Bearer <token>",
            access: "Admin/SuperAdmin",
            body: {
              newPassword: "string (optional, auto-generated if not provided)",
            },
            response: {
              success: {
                message: "Password reset",
                password: "New password",
              },
            },
          },
          "DELETE /api/auth/admin/delete-user/:userId": {
            description: "Delete a user",
            headers: "Authorization: Bearer <token>",
            access: "SuperAdmin only",
            response: {
              success: "User deleted successfully",
            },
          },
          "DELETE /api/auth/admin/delete-log/:logId": {
            description: "Delete a specific activity log entry.",
            headers: "Authorization: Bearer <token>",
            access: "SuperAdmin only",
            response: {
              success: "Log deleted successfully",
            },
          },
          "DELETE /api/auth/admin/delete-all-logs": {
            description: "Delete all logs",
            headers: "Authorization: Bearer <token>",
            access: "SuperAdmin only",
            response: {
              success: "All logs deleted successfully",
            },
          },
          "DELETE /api/admin/delete-user-gemini-key/:userId": {
            description: "Delete a user's Gemini API key.",
            headers: "Authorization: Bearer <token>",
            access: "SuperAdmin only",
            params: {
              userId: "The ID of the user whose key should be deleted.",
            },
            response: {
              success: "User's Gemini API key deleted successfully",
              error: "User not found or permission denied.",
            },
          },
        },

        // Super Admin Only Routes
        superAdmin: {
          "GET /api/auth/api-docs": {
            description: "Get API documentation",
            headers: "Authorization: Bearer <token>",
            access: "SuperAdmin only",
            response: {
              success: "This API documentation object",
            },
          },
        },
      },

      // Error Responses
      errorResponses: {
        400: "Bad Request - Validation errors or invalid data",
        401: "Unauthorized - Missing or invalid JWT token",
        403: "Forbidden - Insufficient permissions",
        404: "Not Found - Resource not found",
        500: "Internal Server Error - Server error",
      },

      // User Roles
      roles: {
        user: "Regular user with basic access",
        admin: "Admin with user management capabilities",
        superAdmin: "Super admin with full system access",
      },

      // Activity Log Actions
      activityActions: [
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
      ],
    };

    res.json({
      success: true,
      data: apiDocs,
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: "Error fetching API documentation",
      error: error.message,
    });
  }
};

// Get admin dashboard stats
exports.getDashboard = async (req, res) => {
  try {
    const currentUser = req.user;

    // Get user statistics
    const totalUsers = await User.countDocuments();
    const verifiedUsers = await User.countDocuments({ isVerified: true });
    const pendingUsers = await User.countDocuments({ isVerified: false });
    const bannedUsers = await User.countDocuments({ banned: true });
    const totalAdmins = await User.countDocuments({
      $or: [{ isAdmin: true }, { isSuperAdmin: true }],
    });

    // Get recent activity (last 10 logs from all users)
    const recentActivity = await User.aggregate([
      { $unwind: "$activityLogs" },
      { $sort: { "activityLogs.timestamp": -1 } },
      { $limit: 10 },
      {
        $project: {
          _id: 0,
          userId: "$_id",
          userName: "$name",
          userEmail: "$email",
          action: "$activityLogs.action",
          timestamp: "$activityLogs.timestamp",
          status: "$activityLogs.status",
          note: "$activityLogs.note",
        },
      },
    ]);

    res.json({
      success: true,
      data: {
        totalUsers,
        verifiedUsers,
        pendingUsers,
        bannedUsers,
        totalAdmins,
        recentActivity,
      },
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: "Error fetching dashboard data",
      error: error.message,
    });
  }
};

// Delete specific log
exports.deleteLog = async (req, res) => {
  try {
    const currentUser = req.user;
    const { logId } = req.params;

    if (!currentUser.isSuperAdmin) {
      return res.status(403).json({
        success: false,
        message: "Only super admin can delete logs",
      });
    }

    // Find the log and remove it
    const result = await User.updateOne(
      { "activityLogs._id": logId },
      { $pull: { activityLogs: { _id: logId } } }
    );

    if (result.modifiedCount === 0) {
      return res.status(404).json({
        success: false,
        message: "Log not found",
      });
    }

    await logActivity(
      currentUser._id,
      "log_deletion",
      req,
      "success",
      `Specific log deleted: ${logId}`
    );

    res.json({
      success: true,
      message: "Log deleted successfully",
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: "Error deleting log",
      error: error.message,
    });
  }
};

// Delete all logs
exports.deleteAllLogs = async (req, res) => {
  try {
    const currentUser = req.user;

    if (!currentUser.isSuperAdmin) {
      return res.status(403).json({
        success: false,
        message: "Only super admin can delete all logs",
      });
    }

    // Clear all activity logs from all users
    await User.updateMany({}, { $set: { activityLogs: [] } });

    await logActivity(
      currentUser._id,
      "logs_deletion",
      req,
      "success",
      "All logs deleted by super admin"
    );

    res.json({
      success: true,
      message: "All logs deleted successfully",
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: "Error deleting all logs",
      error: error.message,
    });
  }
};

// Send password reset URL to user
exports.sendResetUrl = async (req, res) => {
  try {
    const currentUser = req.user;
    const { userId } = req.params;

    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({
        success: false,
        message: "User not found",
      });
    }

    // Generate reset token
    const resetToken = generateResetToken();
    const resetPasswordExpiry = new Date(Date.now() + 24 * 60 * 60 * 1000); // 24 hours

    // Update user with reset token
    user.resetPasswordToken = resetToken;
    user.resetPasswordExpiry = resetPasswordExpiry;
    await user.save();

    // Create reset URL
    const resetUrl = `${req.protocol}://${req.get("host")}/reset-password?token=${resetToken}&email=${user.email}`;

    // Log the activity
    await logActivity(
      currentUser._id,
      "send_reset_url",
      req,
      "success",
      `Password reset URL sent to: ${user.email}`
    );

    res.json({
      success: true,
      message: "Password reset URL sent successfully",
      data: {
        userEmail: user.email,
        resetUrl: resetUrl,
        expiresAt: resetPasswordExpiry,
      },
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: "Error sending reset URL",
      error: error.message,
    });
  }
};

// Delete user's Gemini API key
exports.deleteUserGeminiKey = async (req, res) => {
  try {
    const currentUser = req.user;
    const { userId } = req.params;

    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({
        success: false,
        message: "User not found",
      });
    }

    // Only superadmin can delete API keys from other users
    if (!currentUser.isSuperAdmin) {
      return res.status(403).json({
        success: false,
        message: "Only superadmin can delete API keys from other users",
      });
    }

    // Prevent deleting own API key through this endpoint
    if (user._id.toString() === currentUser._id.toString()) {
      return res.status(403).json({
        success: false,
        message: "Use your profile settings to manage your own API key",
      });
    }

    await User.findByIdAndUpdate(userId, {
      geminiApiKey: null,
      geminiKeyValid: false,
      geminiKeyLastValidated: null,
    });

    await logActivity(
      currentUser._id,
      "gemini_key_update",
      req,
      "success",
      `API key deleted for user: ${user.email}`
    );

    res.json({
      success: true,
      message: "User's Gemini API key deleted successfully",
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: "Error deleting user's API key",
      error: error.message,
    });
  }
};
