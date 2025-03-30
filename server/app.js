require("dotenv").config();
const express = require("express");
const app = express();
const port = process.env.PORT || 3000;
const logger = require("./startup/logger");

app.get("/", (req, res) => res.send("Hello World!"));

app.listen(port, () => {
  logger.info(`Server is running on port ${port}`);
  console.log(`Server is running on port ${port}`);
});
