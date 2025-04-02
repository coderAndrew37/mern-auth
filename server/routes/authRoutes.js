const express = require("express");
const router = express.Router();
const {
  registerUser,
  loginUser,
  logoutUser,
  getCurrentUser,
  sendAccountVerificationOtp,
  verifyAccount,
  authenticate,
  requireVerifiedAccount,
  sendPasswordResetOtp,
  resetPassword,
} = require("../controllers/authController");

// Public routes
router.post("/register", registerUser);
router.post("/login", loginUser);

// Protected routes
router.post("/logout", authenticate, logoutUser);
router.get("/current-user", authenticate, getCurrentUser);

// Verification routes
router.post("/send-verification", authenticate, sendAccountVerificationOtp);
router.post("/verify-account", authenticate, verifyAccount);

// Password reset routes
router.post("/send-password-reset", sendPasswordResetOtp);
router.post("/reset-password", resetPassword);

// Example of a route that requires verified account
router.get(
  "/protected-route",
  authenticate,
  requireVerifiedAccount,
  (req, res) => {
    res.json({ success: true, message: "Verified access" });
  }
);

module.exports = router;
