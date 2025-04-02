require("dotenv").config();
const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const cookieParser = require("cookie-parser");
const compression = require("compression");
const logger = require("./startup/logger");
const authRoutes = require("./routes/authRoutes");
const port = process.env.PORT || 3000;

// Import the MongoDB connection function
const connectDB = require("./startup/db");

// Initialize Express app
const app = express();

// Connect to MongoDB
connectDB();

// Middleware
app.use(express.json());
app.use(cookieParser(process.env.COOKIE_SECRET)); // Add secret to cookie parser
app.use(compression());
app.use(helmet());
app.use(
  cors({
    origin: process.env.CLIENT_URL || "http://localhost:5173",
    methods: ["GET", "POST", "PUT", "DELETE"],
    credentials: true,
  })
);

// Routes
app.get("/", (req, res) => res.send("The server is running!"));
app.use("/api/auth", authRoutes);

// Start server
app.listen(port, () => {
  logger.info(`Server is running on port ${port}`);
  console.log(`Server is running on port ${port}`);
});
