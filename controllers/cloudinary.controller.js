import { v2 as cloudinary } from "cloudinary";
import multer from "multer";
import { CloudinaryStorage } from "multer-storage-cloudinary";

cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
});

const storage = new CloudinaryStorage({
  cloudinary,
  params: async (req, file) => ({
    folder: "blog-uploads",
    allowed_formats: ["jpg", "jpeg", "png", "gif", "webp"],
    transformation: [{ width: 1200, height: 675, crop: "limit" }],
  }),
});

export const upload = multer({
  storage,
  limits: { fileSize: 5 * 1024 * 1024 },
});

export const uploadImage = async (req, res) => {
  console.log("REQ.FILE 👉", req.file); // 🔍 keep this for testing

  if (!req.file) {
    return res.status(400).json({ error: "No image file provided" });
  }

  return res.status(200).json({
    url: req.file.path,
    public_id: req.file.public_id,
  });
};

export const deleteImage = async (req, res) => {
  try {
    const { public_id } = req.body;

    if (!public_id) {
      return res.status(400).json({ error: "No public_id provided" });
    }

    const result = await cloudinary.uploader.destroy(public_id);

    return res.status(200).json({
      message: "Image deleted successfully",
      result,
    });
  } catch (error) {
    console.error("Cloudinary delete error:", error);
    return res.status(500).json({ error: "Failed to delete image" });
  }
};
