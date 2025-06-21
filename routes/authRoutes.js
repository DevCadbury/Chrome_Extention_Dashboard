const express = require("express");
const { body } = require("express-validator");
const authController = require("../controllers/authController");
const adminController = require("../controllers/adminController");
const {
  authenticateToken,
  requireAdmin,
  requireSuperAdmin,
  requireVerified,
} = require("../middleware/auth");

const router = express.Router();

// Validation middleware
const registerValidation = [
  body("name")
    .trim()
    .isLength({ min: 2 })
    .withMessage("Name must be at least 2 characters"),
  body("email").isEmail().withMessage("Please enter a valid email"),
  body("password")
    .isLength({ min: 6 })
    .withMessage("Password must be at least 6 characters"),
];

const loginValidation = [
  body("email").isEmail().withMessage("Please enter a valid email"),
  body("password").notEmpty().withMessage("Password is required"),
];

const forgotPasswordValidation = [
  body("email").isEmail().withMessage("Please enter a valid email"),
];

const resetPasswordValidation = [
  body("email").isEmail().withMessage("Please enter a valid email"),
  body("otp").isLength({ min: 6, max: 6 }).withMessage("OTP must be 6 digits"),
  body("newPassword")
    .isLength({ min: 6 })
    .withMessage("Password must be at least 6 characters"),
];

const changePasswordValidation = [
  body("currentPassword")
    .notEmpty()
    .withMessage("Current password is required"),
  body("newPassword")
    .isLength({ min: 6 })
    .withMessage("New password must be at least 6 characters"),
];

const geminiKeyValidation = [
  body("geminiApiKey").notEmpty().withMessage("Gemini API key is required"),
];

const resetPasswordViaUrlValidation = [
  body("token").notEmpty().withMessage("Reset token is required"),
  body("newPassword")
    .isLength({ min: 6 })
    .withMessage("Password must be at least 6 characters"),
];

const verifyResetTokenValidation = [
  body("token").notEmpty().withMessage("Reset token is required"),
];

// Public routes
router.post("/register", registerValidation, authController.register);
router.post("/login", loginValidation, authController.login);
router.post("/verify-otp", authController.verifyOtp);
router.post(
  "/forgot-password",
  forgotPasswordValidation,
  authController.forgotPassword
);
router.post(
  "/reset-password",
  resetPasswordValidation,
  authController.resetPassword
);
router.post(
  "/verify-reset-token",
  verifyResetTokenValidation,
  authController.verifyResetToken
);
router.post(
  "/reset-password-via-url",
  resetPasswordViaUrlValidation,
  authController.resetPasswordViaUrl
);

// Protected routes (require JWT authentication)
router.get("/profile", authenticateToken, authController.getProfile);
router.post("/logout", authenticateToken, authController.logout);
router.post(
  "/change-password",
  authenticateToken,
  changePasswordValidation,
  authController.changePassword
);
router.post(
  "/validate-gemini-key",
  authenticateToken,
  geminiKeyValidation,
  authController.validateGeminiKey
);
router.put(
  "/update-gemini-key",
  authenticateToken,
  geminiKeyValidation,
  authController.updateGeminiKey
);
router.delete(
  "/remove-gemini-key",
  authenticateToken,
  authController.removeGeminiKey
);

// Admin routes
router.get(
  "/admin/dashboard",
  authenticateToken,
  requireAdmin,
  adminController.getDashboard
);
router.get(
  "/admin/users",
  authenticateToken,
  requireAdmin,
  adminController.getAllUsers
);
router.get(
  "/admin/activity-logs",
  authenticateToken,
  requireAdmin,
  adminController.getActivityLogs
);
router.post(
  "/admin/create-user",
  authenticateToken,
  requireAdmin,
  adminController.createUser
);
router.post(
  "/admin/create-admin",
  authenticateToken,
  requireSuperAdmin,
  adminController.createAdmin
);
router.put(
  "/admin/ban-user/:userId",
  authenticateToken,
  requireAdmin,
  adminController.banUser
);
router.put(
  "/admin/unban-user/:userId",
  authenticateToken,
  requireAdmin,
  adminController.unbanUser
);
router.put(
  "/admin/reset-user-password/:userId",
  authenticateToken,
  requireAdmin,
  adminController.resetUserPassword
);
router.put(
  "/admin/update-user-status/:userId",
  authenticateToken,
  requireAdmin,
  adminController.updateUserStatus
);
router.post(
  "/admin/send-reset-url/:userId",
  authenticateToken,
  requireAdmin,
  adminController.sendResetUrl
);
router.delete(
  "/admin/delete-user/:userId",
  authenticateToken,
  requireSuperAdmin,
  adminController.deleteUser
);
router.delete(
  "/admin/delete-log/:logId",
  authenticateToken,
  requireSuperAdmin,
  adminController.deleteLog
);
router.delete(
  "/admin/delete-all-logs",
  authenticateToken,
  requireSuperAdmin,
  adminController.deleteAllLogs
);

// Delete user's Gemini API key (super admin only)
router.delete(
  "/admin/delete-user-gemini-key/:userId",
  authenticateToken,
  requireSuperAdmin,
  adminController.deleteUserGeminiKey
);

// Super admin only routes
router.get(
  "/api-docs",
  authenticateToken,
  requireSuperAdmin,
  adminController.getApiDocs
);

module.exports = router;
