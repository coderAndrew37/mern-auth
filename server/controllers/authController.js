const { User, userValidation } = require("../models/user.js");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

// Token generation helper
const generateAuthToken = (userId) => {
  return jwt.sign({ id: userId }, process.env.JWT_SECRET, {
    expiresIn: process.env.JWT_EXPIRES_IN || "1d",
  });
};

const register = async (req, res) => {
  try {
    // Validate using Joi schema
    const { error, value } = userValidation.validate(req.body, {
      abortEarly: false,
      stripUnknown: true,
    });

    if (error) {
      const formattedErrors = error.details.map((detail) => ({
        field: detail.path[0],
        message: detail.message.replace(/['"]+/g, ""), // Remove Joi quotes
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
      password: await bcrypt.hash(value.password, 10),
    });

    // Generate and set token
    const token = generateAuthToken(user._id);
    setAuthCookie(res, token);

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
    // Validate credentials
    const { error, value } = userValidation.validate(req.body, {
      abortEarly: false,
      allowUnknown: true,
      stripUnknown: true,
    });

    if (error) {
      const credentialErrors = error.details
        .filter((detail) => ["email", "password"].includes(detail.path[0]))
        .map((detail) => ({
          field: detail.path[0],
          message: detail.message.replace(/['"]+/g, ""),
        }));

      return res.status(400).json({
        success: false,
        message: "Validation failed",
        errors: credentialErrors,
      });
    }

    // Verify credentials
    const user = await User.findOne({ email: value.email }).select(
      "+password +isVerified"
    );

    if (!user || !(await bcrypt.compare(value.password, user.password))) {
      return res.status(401).json({
        success: false,
        message: "Invalid email or password",
      });
    }

    // Generate and set token
    const token = generateAuthToken(user._id);
    setAuthCookie(res, token);

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
  res.json({ success: true, message: "Logged out successfully" });
};

const getCurrentUser = async (req, res) => {
  try {
    const user = await User.findById(req.user.id).select(
      "-password -verifyOtp -resetOtp"
    );

    if (!user) {
      return res.status(404).json({
        success: false,
        message: "User not found",
      });
    }

    res.json({ success: true, user });
  } catch (err) {
    handleAuthError(res, err);
  }
};

// Helper Functions
const getUserResponse = (user) => ({
  id: user._id,
  name: user.name,
  email: user.email,
  isVerified: user.isVerified,
});

const setAuthCookie = (res, token) => {
  res.cookie("token", token, getCookieOptions());
};

const getCookieOptions = () => ({
  httpOnly: true,
  secure: process.env.NODE_ENV === "production",
  sameSite: process.env.NODE_ENV === "production" ? "None" : "Lax",
  maxAge: 24 * 60 * 60 * 1000, // 1 day
  path: "/",
});

const handleAuthError = (res, error) => {
  console.error("Authentication error:", error);

  // Handle Mongoose validation errors
  if (error.name === "ValidationError") {
    const errors = Object.values(error.errors).map((e) => ({
      field: e.path,
      message: e.message,
    }));
    return res.status(400).json({
      success: false,
      message: "Validation failed",
      errors,
    });
  }

  // Handle duplicate key errors
  if (error.code === 11000) {
    return res.status(409).json({
      success: false,
      message: "Email already registered",
      field: "email",
    });
  }

  res.status(500).json({
    success: false,
    message: "Internal server error",
    ...(process.env.NODE_ENV === "development" && { error: error.message }),
  });
};

// authController.js
module.exports = {
  registerUser: register,
  loginUser: login,
  logoutUser: logout,
  getCurrentUser: getCurrentUser,
};
