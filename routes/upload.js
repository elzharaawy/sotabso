import express from "express";
import multer from "multer";
import mongoose from "mongoose";
import { Readable } from "stream";

const router = express.Router();
const upload = multer({ storage: multer.memoryStorage() });

router.post("/image", upload.single("image"), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ error: "No file uploaded" });

    const bucket = new mongoose.mongo.GridFSBucket(mongoose.connection.db, {
      bucketName: "uploads",
    });

    const filename = Date.now() + "-" + req.file.originalname;

    const uploadStream = bucket.openUploadStream(filename, {
      contentType: req.file.mimetype,
    });

    Readable.from(req.file.buffer).pipe(uploadStream);

    uploadStream.on("finish", () => {
      res.status(200).json({ url: `http://localhost:3000/api/uploads/${filename}` });
    });

    uploadStream.on("error", (err) => {
      console.error("GridFS upload error:", err);
      res.status(500).json({ error: "Upload failed" });
    });

  } catch (err) {
    console.error("Upload exception:", err);
    res.status(500).json({ error: "Upload failed" });
  }
});

export default router;
