const joi = require("joi");
const crypto = require("crypto");

const {
  User,
  registerValidation,
  loginValidation,
  otpValidation,
  passwordComplexity,
} = require("../models/user.js");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const transporter = require("../config/email.js");
const { authenticate, requireVerifiedAccount } = require("../middleware/auth");
const rateLimit = require("express-rate-limit");

// Security configurations
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // Limit each IP to 100 requests per window
  standardHeaders: true,
  legacyHeaders: false,
  handler: (req, res) => {
    res.status(429).json({
      success: false,
      message: "Too many requests, please try again later",
    });
  },
});

// Token generation helper
const generateAuthToken = (userId) => {
  return jwt.sign({ id: userId }, process.env.JWT_SECRET, {
    expiresIn: process.env.JWT_EXPIRES_IN || "1d",
    issuer: "your-app-name",
    algorithm: "HS256",
  });
};

const register = async (req, res) => {
  try {
    // Validate input
    const { error, value } = registerValidation.validate(req.body, {
      abortEarly: false,
      stripUnknown: true,
    });

    if (error) {
      const formattedErrors = error.details.map((detail) => ({
        field: detail.path[0],
        message: detail.message.replace(/['"]+/g, ""),
      }));
      return res.status(400).json({
        success: false,
        message: "Validation failed",
        errors: formattedErrors,
      });
    }

    // Check for existing user
    if (await User.exists({ email: value.email })) {
      return res.status(409).json({
        success: false,
        message: "Email already registered",
        field: "email",
      });
    }

    // Create user with hashed password
    const user = await User.create({
      ...value,
      password: await bcrypt.hash(value.password, 12), // Increased salt rounds
    });

    // Generate token and set cookie
    const token = generateAuthToken(user._id);
    setAuthCookie(res, token);

    // Send welcome email (in background)
    transporter
      .sendMail({
        from: `"Secure App" <${process.env.ADMIN_EMAIL}>`,
        to: user.email,
        subject: "Welcome to Our Platform!",
        html: `<p>Hello ${user.name}, welcome to our service!</p>`,
      })
      .catch((err) => console.error("Email send error:", err));

    // Omit sensitive data in response
    res.status(201).json({
      success: true,
      user: getUserResponse(user),
    });
  } catch (err) {
    handleAuthError(res, err);
  }
};

const login = async (req, res) => {
  try {
    // Validate input
    const { error, value } = loginValidation.validate(req.body, {
      abortEarly: false,
    });

    if (error) {
      const errors = error.details.map((detail) => ({
        field: detail.path[0],
        message: detail.message.replace(/['"]+/g, ""),
      }));
      return res.status(400).json({
        success: false,
        message: "Validation failed",
        errors,
      });
    }

    // Find user with password
    const user = await User.findOne({ email: value.email }).select(
      "+password +isVerified +loginAttempts +lockUntil"
    );

    // Account lock check
    if (user?.lockUntil && user.lockUntil > Date.now()) {
      return res.status(403).json({
        success: false,
        message: `Account temporarily locked. Try again after ${Math.ceil(
          (user.lockUntil - Date.now()) / 1000
        )} seconds`,
      });
    }

    // Verify credentials
    if (!user || !(await bcrypt.compare(value.password, user.password))) {
      if (user) {
        // Increment failed attempts
        user.loginAttempts += 1;
        if (user.loginAttempts >= 5) {
          user.lockUntil = Date.now() + 30 * 60 * 1000; // Lock for 30 minutes
        }
        await user.save();
      }

      return res.status(401).json({
        success: false,
        message: "Invalid email or password",
      });
    }

    // Reset login attempts on success
    user.loginAttempts = 0;
    user.lockUntil = undefined;
    await user.save();

    // Generate token and set cookie
    const token = generateAuthToken(user._id);
    setAuthCookie(res, token);

    // Security headers
    res.setHeader("X-Content-Type-Options", "nosniff");
    res.setHeader("X-Frame-Options", "DENY");

    res.json({
      success: true,
      user: getUserResponse(user),
    });
  } catch (err) {
    handleAuthError(res, err);
  }
};

const logout = (req, res) => {
  res.clearCookie("token", getCookieOptions());
  res.json({
    success: true,
    message: "Logged out successfully",
  });
};

const getCurrentUser = async (req, res) => {
  try {
    const user = await User.findById(req.user.id).select(
      "-password -verifyOtp -resetOtp -loginAttempts -lockUntil"
    );

    if (!user) {
      return res.status(404).json({
        success: false,
        message: "User not found",
      });
    }

    res.json({
      success: true,
      user,
    });
  } catch (err) {
    handleAuthError(res, err);
  }
};

const sendAccountVerificationOtp = async (req, res) => {
  try {
    const user = await User.findById(req.user.id);
    if (!user) {
      return res.status(404).json({
        success: false,
        message: "User not found",
      });
    }

    if (user.isVerified) {
      return res.status(400).json({
        success: false,
        message: "User already verified",
      });
    }

    const otp = generateOtp();
    user.verifyOtp = await bcrypt.hash(otp, 8); // Hash OTP
    user.verifyOtpExpireAt = Date.now() + 15 * 60 * 1000; // 15 minutes
    await user.save();

    // Send OTP email
    await transporter.sendMail({
      from: `"Secure App" <${process.env.ADMIN_EMAIL}>`,
      to: user.email,
      subject: "Account Verification OTP",
      html: `<p>Your verification code is: <strong>${otp}</strong></p>
             <p>This code expires in 15 minutes.</p>`,
    });

    res.json({
      success: true,
      message: "OTP sent to your email",
    });
  } catch (err) {
    handleAuthError(res, err);
  }
};

const verifyAccount = async (req, res) => {
  try {
    // Validate OTP
    const { error, value } = otpValidation.validate(req.body);
    if (error) {
      return res.status(400).json({
        success: false,
        message: error.details[0].message,
      });
    }

    const user = await User.findById(req.user.id);
    if (!user) {
      return res.status(404).json({
        success: false,
        message: "User not found",
      });
    }

    if (user.isVerified) {
      return res.status(400).json({
        success: false,
        message: "Account already verified",
      });
    }

    // Verify OTP
    if (
      !user.verifyOtp ||
      !user.verifyOtpExpireAt ||
      !(await bcrypt.compare(value.otp, user.verifyOtp))
    ) {
      return res.status(400).json({
        success: false,
        message: "Invalid OTP",
      });
    }

    if (user.verifyOtpExpireAt < Date.now()) {
      return res.status(400).json({
        success: false,
        message: "OTP expired",
      });
    }

    // Mark as verified
    user.isVerified = true;
    user.verifyOtp = undefined;
    user.verifyOtpExpireAt = undefined;
    await user.save();

    res.json({
      success: true,
      message: "Account verified successfully",
    });
  } catch (err) {
    handleAuthError(res, err);
  }
};

// Password Reset Endpoints
const sendPasswordResetOtp = async (req, res) => {
  try {
    const { error } = joi
      .object({
        email: joi.string().email().required(),
      })
      .validate(req.body);

    if (error)
      return res.status(400).json({
        success: false,
        message: "Valid email required",
      });

    const user = await User.findOne({ email: req.body.email });
    if (user) {
      const otp = generateOtp();
      user.resetOtp = await bcrypt.hash(otp, 10);
      user.resetOtpExpireAt = Date.now() + 15 * 60 * 1000;
      await user.save();

      await transporter.sendMail({
        from: `"Password Reset" <${process.env.ADMIN_EMAIL}>`,
        to: user.email,
        subject: "Your Password Reset Code",
        html: `Your OTP: <strong>${otp}</strong> (expires in 15 minutes)`,
      });
    }

    res.json({
      success: true,
      message: "Password reset OTP was sent to your email",
    });
  } catch (err) {
    handleAuthError(res, err);
  }
};

const resetPassword = async (req, res) => {
  try {
    const { error } = joi
      .object({
        otp: joi.string().length(6).required(),
        newPassword: passwordComplexity.required(),
      })
      .validate(req.body);

    if (error)
      return res.status(400).json({
        success: false,
        message: error.details[0].message,
      });

    const user = await User.findOne({
      resetOtpExpireAt: { $gt: Date.now() },
    });

    if (!user || !(await bcrypt.compare(req.body.otp, user.resetOtp))) {
      return res.status(400).json({
        success: false,
        message: "Invalid/expired OTP",
      });
    }

    user.password = await bcrypt.hash(req.body.newPassword, 12);
    user.resetOtp = undefined;
    user.resetOtpExpireAt = undefined;
    await user.save();

    // Invalidate all sessions
    res.clearCookie("token", getCookieOptions());

    res.json({
      success: true,
      message: "Password updated successfully",
    });
  } catch (err) {
    handleAuthError(res, err);
  }
};

// Helper functions
const generateOtp = () => crypto.randomInt(100000, 999999).toString();

const getUserResponse = (user) => ({
  id: user._id,
  name: user.name,
  email: user.email,
  isVerified: user.isVerified,
});

const setAuthCookie = (res, token) => {
  res.cookie("token", token, {
    ...getCookieOptions(),
    domain: process.env.COOKIE_DOMAIN || undefined,
  });
};

const getCookieOptions = () => ({
  httpOnly: true,
  secure: process.env.NODE_ENV === "production",
  sameSite: process.env.NODE_ENV === "production" ? "Strict" : "Lax",
  maxAge: 24 * 60 * 60 * 1000, // 1 day
  path: "/",
  signed: true, // Requires cookie-parser with secret
});

const handleAuthError = (res, error) => {
  console.error("Authentication error:", error);

  // Don't expose internal errors in production
  const response = {
    success: false,
    message: "Authentication error",
  };

  if (process.env.NODE_ENV === "development") {
    response.error = error.message;
    response.stack = error.stack;
  }

  res.status(500).json(response);
};

const resetLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 5,
  handler: (req, res) => {
    res.status(429).json({
      success: false,
      message: "Too many password reset attempts",
    });
  },
});

module.exports = {
  registerUser: [authLimiter, register],
  loginUser: [authLimiter, login],
  logoutUser: logout,
  getCurrentUser: [authenticate, getCurrentUser],
  sendAccountVerificationOtp: [authenticate, sendAccountVerificationOtp],
  verifyAccount: [authenticate, verifyAccount],
  sendPasswordResetOtp: [resetLimiter, sendPasswordResetOtp],
  resetPassword: [resetLimiter, resetPassword],
  authenticate,
  requireVerifiedAccount,
};
