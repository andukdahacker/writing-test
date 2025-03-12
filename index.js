const express = require("express");
const path = require("path");
const multer = require("multer");
const AWS = require("aws-sdk");
const { v4: uuidv4 } = require("uuid");
const { MongoClient, ObjectId } = require("mongodb");
const jwt = require("jsonwebtoken");
const fs = require("fs");
require("dotenv").config();
const { google } = require("googleapis");
const app = express();
const upload = multer({ dest: "uploads/" });

app.use(express.static("public"));
app.use(express.json());

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
  await mongoClient.connect();
  await mongoClient.db("admin").command({ ping: 1 });

  console.log("Pinged your deployment. You successfully connected to MongoDB!");

  console.log("Connected to MongoDB");
})().catch((e) => {
  console.log("Failed to connect to MongoDB: ", e);
  mongoClient.close();
});
// Google Drive authentication
const auth = new google.auth.GoogleAuth({
  credentials: {
    type: "service_account",
    project_id: process.env.GOOGLE_PROJECT_ID,
    private_key_id: process.env.GOOGLE_PRIVATE_KEY_ID,
    private_key: process.env.GOOGLE_PRIVATE_KEY,
    client_email: process.env.GOOGLE_CLIENT_EMAIL,
  },
  scopes: ["https://www.googleapis.com/auth/drive"],
});

const drive = google.drive({ version: "v3", auth });

async function getFolderId() {
  const folders = await drive.files.list({
    fields: "nextPageToken, files(id,name)",
    spaces: "drive",
  });

  const folder = folders.data.files.filter((x) => {
    return x.name === "Writing Test";
  });

  const folderId = folder.length ? folder[0].id : 0;

  return folderId;
}

async function uploadToDrive(filePath, fileName) {
  const media = {
    mimeType: "text/plain",
    body: fs.createReadStream(filePath),
  };

  try {
    const folderId = await getFolderId();
    const fileMetadata = {
      name: fileName,
      parents: [folderId], // Replace with your Google Drive folder ID
      mimeType: "application/vnd.google-apps.document",
    };
    const response = await drive.files.create({
      requestBody: fileMetadata,
      media: media,
      fields: "id",
    });
    return response.data.id;
  } catch (error) {
    console.error("Error uploading to Drive:", error);
    throw error;
  }
}

app.post("/login", async (req, res) => {
  try {
    const password = req.body.password;
    const db = mongoClient.db();
    const users = db.collection("users");

    const query = {
      password: password,
    };

    const user = await users.findOne(query);

    if (!user) {
      throw new Error("Cannot find user");
    }

    const token = jwt.sign({ id: user._id.toString() }, process.env.JWT_SECRET);

    return res.status(200).json({
      user,
      token,
    });
  } catch (e) {
    console.log("Error logging in: ", e);
    res.status(500).json({ error: "Failed to log in" });
  }
});

async function authMiddleware(req, res, next) {
  const token = req.headers.authorization.split(" ")[1];

  if (!token) {
    return res.status(401).json({ error: "Not authenticated" });
  }

  const decoded = jwt.verify(token, process.env.JWT_SECRET);

  if (!decoded) {
    return res.status(401).json({ error: "Invalid token" });
  }

  req.jwtPayload = decoded.payload;

  next();
}

// Fetch all tests
app.get("/tests", authMiddleware, async (req, res) => {
  try {
    const db = mongoClient.db();
    const tests = await db.collection("tests").find({}).toArray();
    res.status(200).json({ tests });
  } catch (error) {
    console.error("Error fetching tests:", error);
    res.status(500).json({ error: "Failed to fetch tests" });
  }
});

// Fetch a single test by ID
app.get("/test/:id", async (req, res) => {
  try {
    const db = mongoClient.db();
    const test = await db
      .collection("tests")
      .findOne({ _id: new ObjectId(req.params.id) });
    if (!test) return res.status(404).json({ error: "Test not found" });
    res.status(200).json({ test });
  } catch (error) {
    console.error("Error fetching test:", error);
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
      const { title, instructions, timeLimit } = req.body;
      let imageUrl = "";

      if (req.file) {
        const key = `${uuidv4()}_${req.file.originalname}`;
        const fileContent = fs.readFileSync(req.file.path);
        const s3Params = {
          Bucket: S3_BUCKET,
          Key: key,
          Body: fileContent,
          ContentType: req.file.mimetype,
        };
        await s3.upload(s3Params).promise();
        imageUrl = `${process.env.AWS_CLOUDFRONT_DOMAIN}/${key}`;
        fs.unlinkSync(req.file.path);
      }

      const db = mongoClient.db();
      const test = await db
        .collection("tests")
        .insertOne({ title, instructions, timeLimit, imageUrl });
      const testId = test.insertedId;
      const testLink = `http://localhost:${PORT}/test?id=${testId}`;

      res
        .status(200)
        .json({ testId, title, instructions, imageUrl, timeLimit, testLink });
    } catch (error) {
      console.error("Error creating test:", error);
      res.status(500).json({ error: "Failed to create test" });
    }
  }
);

// Endpoint to delete a test
app.delete("/test/:id", authMiddleware, async (req, res) => {
  try {
    const db = mongoClient.db();
    const result = await db
      .collection("tests")
      .deleteOne({ _id: new ObjectId(req.params.id) });
    if (result.deletedCount === 0)
      return res.status(404).json({ error: "Test not found" });
    res.status(200).json({ message: "Test deleted successfully" });
  } catch (error) {
    console.error("Error deleting test:", error);
    res.status(500).json({ error: "Failed to delete test" });
  }
});

app.post("/test/submit", async (req, res) => {
  try {
    const { filename, content } = req.body;
    const filePath = path.join(__dirname, "uploads", filename);
    fs.writeFileSync(filePath, content);

    const fileId = await uploadToDrive(filePath, filename);
    fs.unlinkSync(filePath);

    return res.status(200).json({ message: " Submitted successfully" });
  } catch (e) {
    console.log("Error submitting test: ", e);
    res.status(500).json({ error: "Failed to submit test: " + e });
  }
});

app.use((err, req, res, next) => {
  console.error("Error stack: ", err.stack);
  res.status(500).send("Something broke!");
});

app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${process.env.PORT}`);
});
