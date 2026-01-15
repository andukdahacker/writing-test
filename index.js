const express = require("express");
const path = require("path");
const multer = require("multer");
const AWS = require("aws-sdk");
const { v4: uuidv4 } = require("uuid");
const { MongoClient, ObjectId } = require("mongodb");
const jwt = require("jsonwebtoken");
const fs = require("fs/promises");
require("dotenv").config();
const { google } = require("googleapis");
const { Readable } = require("stream");
const winston = require("winston");

const logger = winston.createLogger({
  level: process.env.LOG_LEVEL || "info",
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.errors({ stack: true }),
    winston.format.splat(),
    winston.format.json()
  ),
  defaultMeta: { service: "writing-test" },
  transports: [
    new winston.transports.Console({
      format: winston.format.combine(
        winston.format.colorize(),
        winston.format.printf(({ level, message, timestamp, ...meta }) => {
          let msg = `${timestamp} [${level}]`;
          if (meta.requestId) msg += ` [${meta.requestId}]`;
          msg += ` ${message}`;
          if (Object.keys(meta).length > 1) {
            msg += `\n${JSON.stringify(meta, null, 2)}`;
          }
          return msg;
        })
      ),
    }),
  ],
});

const app = express();
const upload = multer({ dest: "uploads/" });

const PORT = process.env.PORT;
const domain = "writing-test-production.up.railway.app";

app.use(express.static("public"));
app.use(express.json());

app.use((req, res, next) => {
  req.id = uuidv4();
  res.setHeader("X-Request-ID", req.id);
  next();
});

// Serve the test form page
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

// Serve the test exercise page
app.get("/test", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "test.html"));
});

app.get("/dashboard", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "dashboard.html"));
});

const S3_BUCKET = process.env.AWS_S3_BUCKET;
const s3 = new AWS.S3({
  accessKeyId: process.env.AWS_ACCESS_KEY_ID,
  secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY,
  region: process.env.AWS_REGION,
});

const mongoClient = new MongoClient(process.env.MONGO_URI);
(async () => {
  logger.info("Attempting to connect to MongoDB");
  await mongoClient.connect();
  await mongoClient.db("admin").command({ ping: 1 });

  logger.info("Successfully connected to MongoDB");
})().catch((e) => {
  logger.error("Failed to connect to MongoDB", { error: e.message, stack: e.stack });
  mongoClient.close();
  process.exit(1);
});
// Google Drive authentication
const auth = new google.auth.OAuth2(
  process.env.G_CLIENT_ID,
  process.env.G_CLIENT_SECRET,
  "https://developers.google.com/oauthplayground",
);

auth.setCredentials({
  refresh_token: process.env.G_REFRESH_TOKEN,
});

const drive = google.drive({ version: "v3", auth });

async function getFolderId() {
  logger.debug("Searching for 'Writing Submission' folder in Google Drive");
  const folders = await drive.files.list({
    fields: "nextPageToken, files(id,name)",
    spaces: "drive",
    q: "name = 'Writing Submission' and mimeType = 'application/vnd.google-apps.folder'",
    corpora: "user",
    includeItemsFromAllDrives: true,
    supportsAllDrives: true,
  });

  const folder = folders.data.files.filter((x) => x.name == "Writing Submission");
  const folderId = folder.length ? folder[0].id : null;

  if (!folderId) {
    logger.warn("'Writing Submission' folder not found in Google Drive");
  } else {
    logger.debug(`Found folder with ID: ${folderId}`);
  }

  return folderId;
}

async function uploadToDrive(filePath, fileName) {
  const media = {
    mimeType: "text/plain",
    body: Readable.from(await fs.readFile(filePath)),
  };

  try {
    logger.info(`Uploading file to Google Drive: ${fileName}`);
    const folderId = await getFolderId();

    if (!folderId) {
      throw new Error("'Writing Submission' folder not found");
    }

    const fileMetadata = {
      name: fileName,
      parents: [folderId],
      mimeType: "application/vnd.google-apps.document",
    };

    const response = await drive.files.create({
      requestBody: fileMetadata,
      media: media,
      fields: "id",
      supportsAllDrives: true,
    });

    logger.info(`File uploaded successfully to Google Drive`, { fileId: response.data.id, fileName });
    return response.data.id;
  } catch (error) {
    logger.error("Error uploading to Google Drive", { fileName, error: error.message, stack: error.stack });
    throw error;
  }
}

app.post("/login", async (req, res) => {
  try {
    logger.info("Login attempt", { requestId: req.id });
    const password = req.body.password;
    const db = mongoClient.db();
    const users = db.collection("users");

    const query = {
      password: password,
    };

    const user = await users.findOne(query);

    if (!user) {
      logger.warn("Login failed - user not found", { requestId: req.id });
      return res.status(401).json({ error: "Invalid credentials" });
    }

    const token = jwt.sign({ id: user._id.toString() }, process.env.JWT_SECRET);

    logger.info("Login successful", { requestId: req.id, userId: user._id });
    return res.status(200).json({
      user: { _id: user._id },
      token,
    });
  } catch (e) {
    logger.error("Error during login", { requestId: req.id, error: e.message, stack: e.stack });
    res.status(500).json({ error: "Login failed" });
  }
});

async function authMiddleware(req, res, next) {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader) {
      logger.warn("Authorization header missing", { requestId: req.id, path: req.path });
      return res.status(401).json({ error: "Not authenticated" });
    }

    const token = authHeader.split(" ")[1];
    if (!token) {
      logger.warn("Token missing in authorization header", { requestId: req.id, path: req.path });
      return res.status(401).json({ error: "Not authenticated" });
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    if (!decoded) {
      logger.warn("Invalid token", { requestId: req.id, path: req.path });
      return res.status(401).json({ error: "Invalid token" });
    }

    req.jwtPayload = decoded.payload;
    logger.debug("Authentication successful", { requestId: req.id, path: req.path });
    next();
  } catch (e) {
    logger.error("Authentication failed", { requestId: req.id, path: req.path, error: e.message });
    return res.status(401).json({ error: "Invalid token" });
  }
}

app.get("/tests", authMiddleware, async (req, res) => {
  try {
    logger.info("Fetching all tests", { requestId: req.id });
    const db = mongoClient.db();
    const tests = await db.collection("tests").find({}).toArray();
    logger.info("Tests fetched successfully", { requestId: req.id, count: tests.length });
    res.status(200).json({ tests });
  } catch (error) {
    logger.error("Error fetching tests", { requestId: req.id, error: error.message, stack: error.stack });
    res.status(500).json({ error: "Failed to fetch tests" });
  }
});

app.get("/test/:id", async (req, res) => {
  try {
    logger.info("Fetching test by ID", { requestId: req.id, testId: req.params.id });
    const db = mongoClient.db();
    const test = await db
      .collection("tests")
      .findOne({ _id: new ObjectId(req.params.id) });
    if (!test) {
      logger.warn("Test not found", { requestId: req.id, testId: req.params.id });
      return res.status(404).json({ error: "Test not found" });
    }
    logger.info("Test fetched successfully", { requestId: req.id, testId: req.params.id });
    res.status(200).json({ test });
  } catch (error) {
    logger.error("Error fetching test", { requestId: req.id, testId: req.params.id, error: error.message, stack: error.stack });
    res.status(500).json({ error: "Failed to fetch test" });
  }
});

// Endpoint to create a test
app.post(
  "/create-test",
  authMiddleware,
  upload.single("image"),
  async (req, res) => {
    try {
      logger.info("Creating test", { requestId: req.id });
      const { title, instructions, timeLimit } = req.body;
      let imageUrl = "";

      if (req.file) {
        logger.info("Uploading image to S3", { requestId: req.id, filename: req.file.originalname });
        const key = `${uuidv4()}_${req.file.originalname}`;
        const fileContent = await fs.readFile(req.file.path);
        const s3Params = {
          Bucket: S3_BUCKET,
          Key: key,
          Body: fileContent,
          ContentType: req.file.mimetype,
        };
        await s3.upload(s3Params).promise();
        imageUrl = `${process.env.AWS_CLOUDFRONT_DOMAIN}/${key}`;
        await fs.unlink(req.file.path);
        logger.info("Image uploaded successfully", { requestId: req.id, key });
      }

      const db = mongoClient.db();
      const test = await db
        .collection("tests")
        .insertOne({ title, instructions, timeLimit, imageUrl });
      const testId = test.insertedId;
      const testLink = `${domain}/test?id=${testId}`;

      logger.info("Test created successfully", { requestId: req.id, testId, title });
      res
        .status(200)
        .json({ testId, title, instructions, imageUrl, timeLimit, testLink });
    } catch (error) {
      logger.error("Error creating test", { requestId: req.id, error: error.message, stack: error.stack });
      res.status(500).json({ error: "Failed to create test" });
    }
  },
);

// Endpoint to delete a test
app.delete("/test/:id", authMiddleware, async (req, res) => {
  try {
    logger.info("Deleting test", { requestId: req.id, testId: req.params.id });
    const db = mongoClient.db();
    const result = await db
      .collection("tests")
      .deleteOne({ _id: new ObjectId(req.params.id) });
    if (result.deletedCount === 0) {
      logger.warn("Test not found for deletion", { requestId: req.id, testId: req.params.id });
      return res.status(404).json({ error: "Test not found" });
    }
    logger.info("Test deleted successfully", { requestId: req.id, testId: req.params.id });
    res.status(200).json({ message: "Test deleted successfully" });
  } catch (error) {
    logger.error("Error deleting test", { requestId: req.id, testId: req.params.id, error: error.message, stack: error.stack });
    res.status(500).json({ error: "Failed to delete test" });
  }
});

app.post("/test/submit", async (req, res) => {
  const { filename, content } = req.body;
  const filePath = path.join(__dirname, "uploads", filename);

  try {
    logger.info("Submitting test", { requestId: req.id, filename });
    await fs.writeFile(filePath, content);

    const fileId = await uploadToDrive(filePath, filename);
    await fs.unlink(filePath);

    logger.info("Test submitted successfully", { requestId: req.id, filename, fileId });
    return res.status(200).json({ message: "Submitted successfully" });
  } catch (e) {
    try {
      await fs.unlink(filePath);
    } catch (cleanupError) {
      logger.error("Error cleaning up file", { requestId: req.id, filePath, error: cleanupError.message });
    }
    logger.error("Error submitting test", { requestId: req.id, filename, error: e.message, stack: e.stack });
    res.status(500).json({ error: "Failed to submit test" });
  }
});

app.use((err, req, res, next) => {
  logger.error("Unhandled error", {
    requestId: req.id,
    path: req.path,
    method: req.method,
    error: err.message,
    stack: err.stack,
  });
  res.status(500).json({ error: "Internal server error" });
});

app.listen(PORT, () => {
  logger.info(`Server started`, { domain, port: PORT });
  logger.info(`Server running on https://${domain}:${PORT}`);
});
