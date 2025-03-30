const mongoose = require("mongoose");
const logger = require("./logger");

module.exports = function connectDB() {
  const connectionOptions = {
    useCreateIndex: true,
    useFindAndModify: false,
  };

  mongoose
    .connect(process.env.MONGODB_URI)
    .then(() => console.log("Connected to MongoDB"))
    .catch((err) => {
      logger.error("MongoDB connection error:" + err);
      process.exit(1); // Exit process with failure
    });

  mongoose.connection.on("error", (err) => {
    logger.error("MongoDB connection error:", err);
  });

  mongoose.connection.on("disconnected", () => {
    logger.warn("MongoDB disconnected");
  });

  mongoose.connection.on("connected", () => {
    logger.info("MongoDB connected");
  });

  mongoose.connection.on("reconnected", () => {
    logger.info("MongoDB reconnected");
  });
};
