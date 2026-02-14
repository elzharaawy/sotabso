import express from "express";
import mongoose from "mongoose";

const router = express.Router();

router.get("/:filename", async (req, res) => {
  try {
    const bucket = new mongoose.mongo.GridFSBucket(mongoose.connection.db, {
      bucketName: "uploads",
    });

    const file = await mongoose.connection.db
      .collection("uploads.files")
      .findOne({ filename: req.params.filename });

    if (!file) return res.status(404).json({ error: "File not found" });

    res.set("Content-Type", file.contentType);
    bucket.openDownloadStreamByName(req.params.filename).pipe(res);
  } catch (err) {
    console.error("Image fetch error:", err);
    res.status(500).json({ error: "Failed to fetch image" });
  }
});

export default router;
