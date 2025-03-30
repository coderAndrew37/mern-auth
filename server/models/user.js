const mongoose = require("mongoose");
const joi = require("joi");
const joiPassword = require("joi-password-complexity");

const userSchema = new mongoose.Schema({
  name: {
    type: String,
    required: [true, "Please provide your name"],
    minlength: [3, "Name must be at least 3 characters long"],
    maxlength: [30, "Name cannot exceed 30 characters"],
    trim: true,
  },
  email: {
    type: String,
    required: [true, "Please provide your email"],
    unique: [true, "This email is already registered"],
    lowercase: true,
    validate: {
      validator: function (v) {
        return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v);
      },
      message: "Please provide a valid email address",
    },
  },
  password: {
    type: String,
    required: [true, "Please provide a password"],
    minlength: [8, "Password must be at least 8 characters long"],
    select: false,
  },
  verifyOtp: {
    type: String,
    default: "",
  },
  verifyOtpExpireAt: {
    type: Number, // Fixed: changed 'number' to 'Number'
    default: 0,
  },
  isVerified: {
    type: Boolean,
    default: false,
  },
  resetOtp: {
    type: String,
    default: "",
  },
  resetOtpExpireAt: {
    type: Number, // Fixed: changed 'number' to 'Number'
    default: 0,
  },

  createdAt: {
    type: Date,
    default: Date.now,
  },
});

const User = mongoose.models.User || mongoose.model("User", userSchema);

const passwordComplexity = joiPassword({
  min: 8,
  max: 20,
  lowerCase: 1,
  upperCase: 1,
  numeric: 1,
  symbol: 1,
  requirementCount: 2,
}).messages({
  "password.min": "Password must be at least 8 characters long",
  "password.max": "Password cannot exceed 20 characters",
  "password.lowerCase": "Password must contain at least 1 lowercase letter",
  "password.upperCase": "Password must contain at least 1 uppercase letter",
  "password.numeric": "Password must contain at least 1 number",
  "password.symbol": "Password must contain at least 1 special character",
  "password.requirementCount":
    "Password must meet at least 2 of the complexity requirements",
});

const userValidation = joi
  .object({
    name: joi.string().required().min(3).max(30).messages({
      "string.empty": "Please provide your name",
      "string.min": "Name must be at least 3 characters long",
      "string.max": "Name cannot exceed 30 characters",
      "any.required": "Name is required",
    }),
    email: joi.string().email().required().min(10).max(50).messages({
      "string.email": "Please provide a valid email address",
      "string.empty": "Please provide your email",
      "string.min": "Email must be at least 10 characters long",
      "string.max": "Email cannot exceed 50 characters",
      "any.required": "Email is required",
    }),
    password: passwordComplexity,
    verifyOtp: joi.string(),
    verifyOtpExpireAt: joi.number(),
    isVerified: joi.boolean(),
    resetOtp: joi.string(),
    resetOtpExpireAt: joi.number(),
  })
  .messages({
    "object.unknown": "Invalid field: {#label}",
  });

module.exports = { User, userValidation };
