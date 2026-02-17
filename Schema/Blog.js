import mongoose, { Schema } from "mongoose";

const blogSchema = mongoose.Schema({
    blog_id: {
        type: String,
        required: true,
        unique: true,
    },
    title: {
        type: String,
        required: true,
    },
    banner: {
        type: String,
        // required: true,
    },
    banner_public_id: {
        type: String, // Cloudinary public_id for deletion
    },
    des: {
        type: String,
        maxlength: 200,
        // required: true
    },
    content: {
        type: [],
        // required: true
    },
    tags: {
        type: [String],
        // required: true
    },
    author: {
        type: Schema.Types.ObjectId,
        required: true,
        ref: 'users'
    },
    activity: {
        total_likes: {
            type: Number,
            default: 0
        },
        total_comments: {
            type: Number,
            default: 0
        },
        total_reads: {
            type: Number,
            default: 0
        },
        total_parent_comments: {
            type: Number,
            default: 0
        },
    },
    comments: {
        type: [Schema.Types.ObjectId],
        ref: 'comments'
    },
    draft: {
        type: Boolean,
        default: false
    }
}, 
{ 
    timestamps: {
        createdAt: 'publishedAt'
    } 
});

// Middleware to delete Cloudinary image when blog is deleted
blogSchema.pre('deleteOne', { document: true, query: false }, async function() {
    if (this.banner_public_id) {
        try {
            const cloudinary = require('cloudinary').v2;
            await cloudinary.uploader.destroy(this.banner_public_id);
            console.log(`Deleted banner image: ${this.banner_public_id}`);
        } catch (error) {
            console.error('Failed to delete banner from Cloudinary:', error);
        }
    }
});

// Middleware to delete old banner when updating with a new one
blogSchema.pre('save', async function(next) {
    if (this.isModified('banner_public_id') && !this.isNew) {
        const oldDoc = await this.constructor.findById(this._id);
        if (oldDoc && oldDoc.banner_public_id && oldDoc.banner_public_id !== this.banner_public_id) {
            try {
                const cloudinary = require('cloudinary').v2;
                await cloudinary.uploader.destroy(oldDoc.banner_public_id);
                console.log(`Deleted old banner: ${oldDoc.banner_public_id}`);
            } catch (error) {
                console.error('Failed to delete old banner:', error);
            }
        }
    }
    next();
});

export default mongoose.model("blogs", blogSchema);