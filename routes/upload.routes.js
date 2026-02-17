import express from "express";
import { upload, uploadImage, deleteImage } from "../controllers/cloudinary.controller.js";

const router = express.Router();

router.post("/upload/image", upload.single("image"), uploadImage);
router.post("/delete/image", deleteImage);

export default router;
