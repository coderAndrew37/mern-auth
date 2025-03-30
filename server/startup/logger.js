const { createLogger, format, transports } = require("winston");
const { MongoDB } = require("winston-mongodb");
const RotateFile = require("winston-daily-rotate-file");

const logger = createLogger({
  level: process.env.LOG_LEVEL,
  format: format.combine(
    format.timestamp(),
    format.errors({ stack: true }),
    format.json()
  ),
  transports: [
    new RotateFile({
      filename: "./logs/%DATE%.log",
      datePattern: "YYYY-MM-DD",
      zippedArchive: true,
      maxSize: "20m",
      maxFiles: "14d",
    }),
    new MongoDB({
      level: process.env.LOG_LEVEL,
      collection: "logs",
      db: process.env.MONGODB_URI,
    }),
  ],
});

module.exports = logger;
