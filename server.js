import express from "express";
import mongoose from "mongoose";
import "dotenv/config";
import bcrypt from "bcrypt";
import { nanoid } from "nanoid";
import jwt from "jsonwebtoken";
import cors from "cors";
import admin from "firebase-admin";
import uploadRoutes from "./routes/upload.js";
import uploadsServe from "./routes/uploads.js";

//import serviceAcountKey from "./blogsite-a9422-firebase-adminsdk-fbsvc-c271048519.json" assert { type:"json" };
import { getAuth } from "firebase-admin/auth";
import fs from "fs";




const serviceAcountKey = JSON.parse(
  fs.readFileSync("./blogsite-a9422-firebase-adminsdk-fbsvc-c271048519.json", "utf8")
);

//schema below
import User from "./Schema/User.js";
import Blog from "./Schema/Blog.js";
import Notification from "./Schema/Notification.js";
import Comment from "./Schema/Comment.js";

const server = express();
const PORT = 3000;

admin.initializeApp({
  credential: admin.credential.cert(serviceAcountKey)
});

let emailRegex = /^\w+([\.-]?\w+)*@\w+([\.-]?\w+)*(\.\w{2,3})+$/;
let passwordRegex = /^(?=.*\d)(?=.*[a-z])(?=.*[A-Z]).{6,20}$/;

server.use(express.json());
server.use(cors());

// ⬇upload banner
server.use("/api/upload", uploadRoutes);
server.use("/api/uploads", uploadsServe);


mongoose.set("debug", true);

mongoose.connect(process.env.DB_LOCATION, {
  autoIndex: true,
  serverSelectionTimeoutMS: 10000,
  tls: true,
})
  .then(() => console.log("MongoDB connected successfully"))
  .catch((err) => console.error("MongoDB connection error:", err));

const generateUsername = async (email) => {
  let username = email.split("@")[0];

  let isUsernameNotUnique = await User.exists({
    "personal_info.username": username,
  });

  if (isUsernameNotUnique) username += nanoid().substring(0, 5);

  return username;
};

const verifyJWT = (req, res, next) => {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];

  if (token == null) {
    return res.status(401).json({ error: "No access token" });
  }

  jwt.verify(token, process.env.SECRET_ACCESS_KEY, (err, user) => {
    if (err) {
      return res.status(403).json({ error: "Access token is invalid" });
    }

    req.user = user.id;
    req.admin = user.admin
    next();
  });
};



const formatDataToSend = (user) => {
  const access_token = jwt.sign(
    { id: user._id, admin: user.admin },
    process.env.SECRET_ACCESS_KEY,
    { expiresIn: "7d" }
  );

  return {
    access_token,
    profile_img: user.personal_info.profile_img,
    username: user.personal_info.username,
    fullname: user.personal_info.fullname,
    isAdmin: user.admin
  };
};

server.post("/signup", async (req, res) => {
  let { fullname, email, password } = req.body;

  if (fullname.length < 3)
    return res.status(400).json({ error: "Fullname must be at least 3 letters long" });

  if (!email.length)
    return res.status(400).json({ error: "Enter Email" });

  if (!emailRegex.test(email))
    return res.status(400).json({ error: "Email is invalid" });

  if (!passwordRegex.test(password))
    return res.status(400).json({
      error:
        "Password should be 6 to 20 characters long with a numeric, 1 lowercase and 1 uppercase letters",
    });

  try {
    const existingUser = await User.exists({ "personal_info.email": email });
    if (existingUser)
      return res.status(409).json({ error: "Email already exists" });

    const hashed_password = await bcrypt.hash(password, 10);
    const username = await generateUsername(email);

    let user = new User({
      personal_info: {
        fullname,
        email,
        password: hashed_password,
        username,
      },
    });

    const savedUser = await user.save();
    return res.status(200).json(formatDataToSend(savedUser));
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

server.post("/signin", async (req, res) => {
  try {
    let { email, password } = req.body;

    email = email.toLowerCase().trim();

    const user = await User.findOne({ "personal_info.email": email });

    if (!user) {
      return res.status(403).json({ error: "No account found with this email" });
    }

    if (user.google_auth && !user.personal_info.password) {
      return res.status(403).json({
        error: "Account was created using Google. Please login with Google."
      });
    }


    const isMatch = await bcrypt.compare(password, user.personal_info.password);

    if (!isMatch) {
      return res.status(403).json({ error: "Incorrect password" });
    }

    return res.status(200).json(formatDataToSend(user));

  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: "Server error while logging in" });
  }
});


server.post("/google-auth", async (req, res) => {
  try {
    const { access_token } = req.body;

    const decodedUser = await getAuth().verifyIdToken(access_token);

    let { email, picture } = decodedUser;
    let name = decodedUser.name || decodedUser.displayName || "User";

    picture = picture.replace("s96-c", "s384-c");

    let user = await User.findOne({ "personal_info.email": email })
      .select("personal_info.fullname personal_info.username personal_info.profile_img google_auth");

    if (user) {
      if (!user.google_auth) {
        return res.status(403).json({
          error: "This email was signed up without google. Please log in with password to access the account",
        });
      }
    } else {
      const username = await generateUsername(email);

      user = new User({
        personal_info: {
          fullname: name,
          email,
          username,
          profile_img: picture,
        },
        google_auth: true,
      });

      user = await user.save();
    }

    return res.status(200).json(formatDataToSend(user));
  } catch (err) {
    console.error(err);
    return res.status(500).json({
      error: "Failed to authenticate you with google. Try with some other google account",
    });
  }
});

server.post("/change-password", verifyJWT, (req, res) => {

  let { currentPassword, newPassword } = req.body;

  if (
    !passwordRegex.test(currentPassword) ||
    !passwordRegex.test(newPassword)
  ) {
    return res.status(403).json({
      error:
        "Password should be 6 to 20 characters long with a numeric, 1 lowercase and 1 uppercase letters",
    });
  }

  User.findOne({ _id: req.user })
    .then((user) => {
      if (user.google_auth) {
        return res.status(403).json({
          error:
            "You can't change account's password because you logged in through google",
        })
      }
      bcrypt.compare(
  currentPassword,
  user.personal_info.password,
  (err, result) => {

    if (err) {
      return res.status(500).json({
        error:
          "Some error occured while changing the password, please try again later",
      });
    }

    if (!result) {
      return res.status(403).json({
        error: "Incorrect current password",
      });
    }

    bcrypt.hash(newPassword, 10, (err, hashed_password) => {

      User.findOneAndUpdate(
        { _id: req.user },
        { "personal_info.password": hashed_password }
      )
        .then((u) => {
          return res.status(200).json({
            status: "password changed",
          });
        })
        .catch((err) => {
          return res.status(500).json({
            error:
              "Some error occured while saving new password, please try again later",
          });
        });

    });

  }
);
    })
    .catch(err => {
  console.log(err);
  res.status(500).json({ error: "User not found" });
})


});


//latest blogs 
server.post("/latest-blogs", (req, res) => {

  let {page}=req.body;

  let maxLimit = 5;

  Blog.find({ draft: false })
    .populate(
      "author",
      "personal_info.profile_img personal_info.username personal_info.fullname -_id"
    )
    .sort({ publishedAt: -1 })
    .select("blog_id title des banner activity tags publishedAt -_id")
    .skip((page - 1)* maxLimit)
    .limit(maxLimit)
    .then(blogs => {
      return res.status(200).json({ blogs });
    })
    .catch(err => {
      return res.status(500).json({ error: err.message });
    });

});

server.post("/all-latest-blogs-count", (req, res) => {
  Blog.countDocuments({ draft: false })
    .then((count) => {
      return res.status(200).json({ totalDocs: count });
    })
    .catch((err) => {
      console.log(err.message);
      return res.status(500).json({ error: err.message });
    });
});


//trending blogs
server.get("/trending-blogs", (req, res) => {

  Blog.find({ draft: false })
    .populate("author", "personal_info.profile_img personal_info.username personal_info.fullname -_id")
    .sort({ "activity.total_read": -1, "activity.total_likes": -1, "publishedAt": -1 })
    .select("blog_id title publishedAt -_id")
    .limit(5)
    .then(blogs => {
      return res.status(200).json({ blogs });
    })
    .catch(err => {
      return res.status(500).json({ error: err.message });
    });

});


// blog search
server.post("/search-blogs", async (req, res) => {
  let { tag, query, author, page, limit, eliminate_blog } = req.body;
  let findQuery = { draft: false };

  try {
    if (author) {
      const user = await User.findOne(
        { "personal_info.username": author },
        "_id"
      );

      if (!user) {
        return res.status(200).json({ blogs: [] });
      }

      findQuery.author = user._id;
    }

    if (tag) {
  findQuery.tags = tag;
}

    // exclude current blog (for similar posts)
    if (eliminate_blog) {
      findQuery.blog_id = { $ne: eliminate_blog };
    }

    if (query) {
      findQuery.title = new RegExp(query, "i");
    }

    let maxLimit = limit ? limit: 2 ;

    const blogs = await Blog.find(findQuery)
      .populate(
        "author",
        "personal_info.profile_img personal_info.username personal_info.fullname -_id"
      )
      .sort({ publishedAt: -1 })
      .select("blog_id title des banner activity tags publishedAt -_id")
      .skip((page - 1) * maxLimit)
      .limit(maxLimit);

    return res.status(200).json({ blogs });
  } catch (err) {
    console.error("SEARCH BLOGS ERROR:", err);
    return res.status(500).json({ error: err.message });
  }
});



server.post("/search-blogs-count", async (req, res) => {
  let { tag, author, query } = req.body;
  let findQuery = { draft: false };

  try {
    if (author) {
      const user = await User.findOne(
        { "personal_info.username": author },
        "_id"
      );

      if (!user) {
        return res.status(200).json({ totalDocs: 0 });
      }

      findQuery.author = user._id;
    }

   if (tag) {
  findQuery.tags = tag;
}


    if (query) {
      findQuery.$or = [
        { title: { $regex: query, $options: "i" } },
        { tags: { $in: [new RegExp(query, "i")] } },
      ];
    }

    const count = await Blog.countDocuments(findQuery);
    return res.status(200).json({ totalDocs: count });
  } catch (err) {
    console.error("COUNT ERROR:", err);
    return res.status(500).json({ error: err.message });
  }
});

//search users 
server.post("/search-users", (req, res) => {
  let { query } = req.body;

  User.find({
    "personal_info.username": new RegExp(query, "i"),
  })
    .limit(50)
    .select(
      "personal_info.fullname personal_info.username personal_info.profile_img -_id"
    )
    .then((users) => {
      return res.status(200).json({ users });
    })
    .catch((err) => {
      return res.status(500).json({ error: err.message });
    });
});

// users page 

server.post("/get-profile", (req, res) => {
  let { username } = req.body;

  User.findOne({ "personal_info.username": username })
    .select("-personal_info.password -google_auth -updatedAt -blogs")
    .then(user => {
      return res.status(200).json(user);
    })
    .catch(err => {
      console.log(err);
      return res.status(500).json({ error: err.message });
    });
});

//update profile 
server.post("/update-profile-img", verifyJWT, (req, res) => {
  const { profile_img } = req.body;

  User.findOneAndUpdate(
    { _id: req.user },
    { "personal_info.profile_img": profile_img },
    { new: true }
  )
    .then(() => {
      return res.status(200).json({ profile_img });
    })
    .catch((err) => {
      return res.status(500).json({ error: err.message });
    });
});


server.post("/update-profile", verifyJWT, (req, res) => {
  const { username, bio, social_links } = req.body;
  const bioLimit = 150;

  if (username.length < 3) {
    return res
      .status(403)
      .json({ error: "Username should be at least 3 letters long" });
  }

  if (bio.length > bioLimit) {
    return res
      .status(403)
      .json({ error: `Bio should not be more than ${bioLimit} characters` });
  }

  const socialLinksArr = Object.keys(social_links);

  try {
    for (let i = 0; i < socialLinksArr.length; i++) {
      const key = socialLinksArr[i];
      const value = social_links[key];

      if (value.length) {
        const hostname = new URL(value).hostname;

        if (!hostname.includes(`${key}.com`) && key !== "website") {
          return res.status(403).json({
            error: `${key} link is invalid`,
          });
        }
      }
    }
  } catch (err) {
    return res.status(500).json({
      error: "You must provide full social links with http(s) included",
    });
  }

  const updateObj = {
    "personal_info.username": username,
    "personal_info.bio": bio,
    social_links,
  };

  User.findOneAndUpdate(
    { _id: req.user },
    updateObj,
    { runValidators: true }
  )
    .then(() => {
      return res.status(200).json({ username });
    })
    .catch((err) => {
      if (err.code === 11000) {
        return res
          .status(409)
          .json({ error: "Username is already taken" });
      }

      return res.status(500).json({ error: err.message });
    });
});
  





//blogging section 

server.post('/create-blog', verifyJWT, async (req, res) => {

  let authorId = req.user;
  let isAdmin = req.admin;

if(isAdmin){
  let { title, des, banner, tags, content, draft, id } = req.body;

  if (!title || !title.length) {
    return res.status(403).json({ error: "You must provide a title" });
  }
  if (!draft) {

    if (!des || !des.length || des.length > 200) {
    return res.status(403).json({ error: "You must provide blog description under 200 characters" });
  }

  if (!banner || !banner.length) {
    return res.status(403).json({ error: "You must provide blog banner to publish it" });
  }

  if (!content || !content.blocks || !content.blocks.length) {
    return res.status(403).json({ error: "There must be some blog content to publish it" });
  }

  if (!tags || !tags.length || tags.length > 10) {
    return res.status(403).json({ error: "Provide tags in order to publish the blog, Maximum 10" });
  }
}

  tags = tags.map(tag => tag.toLowerCase());

  const blog_id = id || title.replace(/[^a-zA-Z0-9]/g, " ").replace(/\s+/g, "-").trim() + nanoid();
  
  if(id){
    Blog.findOneAndUpdate(
  { blog_id },
  { title, des, banner, content, tags, draft: draft ? draft : false }
)
  .then(() => {
    return res.status(200).json({ id: blog_id });
  })
  .catch(err => {
    return res.status(500).json({ error: err.message });
  });

  }else {

    try {
    let blog = new Blog({
      title,
      des,
      banner,
      content,
      tags,
      author: authorId,
      blog_id: blog_id,
      draft: Boolean(draft)
    });

    await blog.save();

    let incrementVal = draft ? 0 : 1;

    let user = await User.findByIdAndUpdate(
      authorId,
      {
        $inc: { "account_info.total_posts": incrementVal },
        $push: { blogs: blog._id }
      },
      { new: true }
    );

    if (!user) {
      return res.status(404).json({ error: "User not found while updating blog count" });
    }

    return res.status(200).json({ id: blog.blog_id });

  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: err.message });
  }

  }

}else {
  return res.status(500).json({ error: "you don't have permissions to create any blog" });
}
  
});

// blog page
server.post("/get-blog", (req, res) => {
  let { blog_id, draft, mode } = req.body;

  let incrementVal = mode !== "edit" ? 1 : 0;


  Blog.findOneAndUpdate(
    { blog_id },
    { $inc: { "activity.total_reads": incrementVal } }
  )
    .populate(
      "author",
      "personal_info.fullname personal_info.username personal_info.profile_img"
    )
    .select("title des content banner activity publishedAt blog_id tags")
    .then((blog) => {

      User.findOneAndUpdate(
  { "personal_info.username": blog.author.personal_info.username },
  { $inc: { "account_info.total_reads": incrementVal } }
)
  .catch(err => {
    return res.status(500).json({ error: err.message });
  });

  if (blog.draft && !draft) {
  return res.status(500).json({ error: "you can not access draft blogs" });
}


      return res.status(200).json({ blog });
    })
    .catch((err) => {
      return res.status(500).json({ error: err.message });
    });
});

// like blog
server.post("/like-blog", verifyJWT, (req, res) => {

  let user_id = req.user;
  let { _id, islikedByUser } = req.body;

  let incrementVal = !islikedByUser ? 1 : -1;

  Blog.findOneAndUpdate(
    { _id },
    { $inc: { "activity.total_likes": incrementVal } }
  )
  .then(blog => {

    if(!islikedByUser){

      let like = new Notification({
        type: "like",
        blog: _id,
        notification_for: blog.author,
        user: user_id
      })

      like.save().then(() => {
        return res.status(200).json({ liked_by_user: true })
      })

    } else{

      Notification.findOneAndDelete({
        user: user_id,
        blog: _id,
        type: "like"
      })
      .then(() => {
        return res.status(200).json({ liked_by_user: false })
      })
      .catch(err => {
        return res.status(500).json({ error: err.message })
      })

    }

  })

})

// is liked by user 

server.post("/isliked-by-user", verifyJWT, (req, res) => {

  let user_id = req.user;
  let { _id } = req.body;

  Notification.exists({ user: user_id, type: "like", blog: _id })
  .then(result => {
    return res.status(200).json({ result })
  })
  .catch(err => {
    return res.status(500).json({ error: err.message })
  })

})


server.post("/add-comment", verifyJWT, (req, res) => {
  let user_id = req.user;

  let { _id, comment, blog_author, replying_to, notification_id } = req.body;

  if (!comment.length) {
    return res
      .status(403)
      .json({ error: "Write something to leave a comment" });
  }

  // creating a comment doc
  let commentObj = new Comment({
    blog_id: _id,
    blog_author,
    comment,
    commented_by: user_id,
  });
  if (replying_to) {
  commentObj.parent = replying_to;
  commentObj.isReply = true;
}


new Comment(commentObj).save().then(async (commentFile) => {
  let { comment, commentedAt, children } = commentFile;

  Blog.findOneAndUpdate(
    { _id },
    {
      $push: { comments: commentFile._id },
      $inc: {
        "activity.total_comments": 1,
        "activity.total_parent_comments": replying_to ? 0: 1 ,
      },
    }
  ).then((blog) => {
    console.log("New comment created");
  });

  let notificationObj = {
    type: replying_to ? "reply" : "comment",
    blog: _id,
    notification_for: blog_author,
    user: user_id,
    comment: commentFile._id,
  };

  if (replying_to) {
  notificationObj.replied_on_comment = replying_to;

  await Comment.findOneAndUpdate(
    { _id: replying_to },
    { $push: { children: commentFile._id } }
  ).then((replyingToCommentDoc) => {
    notificationObj.notification_for =
      replyingToCommentDoc.commented_by;
  });
  if (notification_id) {
  Notification.findOneAndUpdate(
    { _id: notification_id },
    { reply: commentFile._id }
  )
  .then(notification => {
    console.log("notification updated");
  })
  .catch(err => {
    console.log(err);
  });
}

}

  new Notification(notificationObj)
    .save()
    .then((notification) => console.log("new notification created"));

  return res.status(200).json({
  comment, commentedAt, _id: commentFile._id, user_id,children
});

});
});


server.post("/get-blog-comments", (req, res) => {
  let { blog_id, skip } = req.body;

  let maxLimit = 5;

  Comment.find({ blog_id, isReply: false })
    .populate(
      "commented_by",
      "personal_info.username personal_info.fullname personal_info.profile_img"
    )
    .skip(skip)
    .limit(maxLimit)
    .sort({
      commentedAt: -1,
    })
    .then(comment => {
      return res.status(200).json(comment);
    })
    .catch(err => {
      console.log(err.message);
      return res.status(500).json({ error: err.message });
    });
});


server.post("/get-replies", (req, res) => {
  let { _id, skip } = req.body;

  let maxLimit = 5;

  Comment.findOne({ _id })
    .populate({
      path: "children",
      options: {
        limit: maxLimit,
        skip: skip,
        sort: { commentedAt: -1 },
      },
      populate: {
        path: "commented_by",
        select:
          "personal_info.profile_img personal_info.fullname personal_info.username",
      },
      select: "-blog_id -updatedAt",
    })
    .select("children")
    .then((doc) => {
      return res.status(200).json({ replies: doc.children });
    })
    .catch((err) => {
      return res.status(500).json({ error: err.message });
    });
});

// delete comments 
server.post("/delete-comment", verifyJWT, async (req, res) => {
  let user_id = req.user;
  let { _id } = req.body;

  const session = await mongoose.startSession();
  session.startTransaction();

  try {
    // Find comment with session
    const comment = await Comment.findOne({ _id }).session(session);
    
    if (!comment) {
      await session.abortTransaction();
      return res.status(404).json({ error: "Comment not found" });
    }

    // Convert ObjectIds to strings for comparison
    if (user_id !== comment.commented_by.toString() && 
        user_id !== comment.blog_author.toString()) {
      await session.abortTransaction();
      return res.status(403).json({ error: "You cannot delete this comment" });
    }

    // Delete comment and all its children
    await deleteComments(_id, session);
    
    await session.commitTransaction();
    return res.status(200).json({ status: "done" });

  } catch (err) {
    await session.abortTransaction();
    console.error(err);
    return res.status(500).json({ error: "Failed to delete comment" });
  } finally {
    session.endSession();
  }
});

const deleteComments = async (_id, session) => {
  const comment = await Comment.findOneAndDelete({ _id }).session(session);
  
  if (!comment) return;

  // Remove from parent comment's children array
  if (comment.parent) {
    await Comment.findOneAndUpdate(
      { _id: comment.parent },
      { $pull: { children: _id } }
    ).session(session);
  }

  // Delete notifications related to this comment
  await Notification.deleteMany({ 
    $or: [
      { comment: _id },
      { replied_on_comment: _id }
    ]
  }).session(session);

  // Update notifications that have this comment as a reply - remove the reply field
  await Notification.findOneAndUpdate(
    { reply: _id },
    { $unset: { reply: 1 } }
  ).session(session);

  // Update blog counts
  await Blog.findOneAndUpdate(
    { _id: comment.blog_id },
    {
      $pull: { comments: _id },
      $inc: {
        "activity.total_comments": -1,
        "activity.total_parent_comments": comment.parent ? 0 : -1,
      },
    }
  ).session(session);

  // Recursively delete all child comments
  if (comment.children && comment.children.length) {
    for (const childId of comment.children) {
      await deleteComments(childId, session);
    }
  }
};


// Notification Routes

server.get("/new-notification", verifyJWT, (req, res) => {
    let user_id = req.user; // Keep as req.user since that's what your verifyJWT sets

    Notification.exists({
        notification_for: user_id,
        seen: false,
        user: { $ne: user_id }
    })
    .then(result => {
        if (result) {
            return res.status(200).json({ new_notification_available: true });
        } else {
            return res.status(200).json({ new_notification_available: false });
        }
    })
    .catch(err => {
        console.log(err.message);
        return res.status(500).json({ error: err.message });
    });
});

server.post("/notifications", verifyJWT, (req, res) => {
    let user_id = req.user; // ✅ Changed from req.id to req.user for consistency

    let { page, filter, deletedDocCount } = req.body;

    let maxLimit = 10;
    let skipDocs = (page - 1) * maxLimit;

    let findQuery = { notification_for: user_id, user: { $ne: user_id } };

    if (filter != 'all') {
        findQuery.type = filter;
    }

    if (deletedDocCount) {
        skipDocs -= deletedDocCount;
    }

    Notification.find(findQuery)
        .skip(skipDocs)
        .limit(maxLimit)
        .populate("blog", "title blog_id")
        .populate("user", "personal_info.fullname personal_info.username personal_info.profile_img")
        .populate("comment", "comment")
        .populate("replied_on_comment", "comment")
        .populate("reply", "comment")
        .sort({ createdAt: -1 })
        .select("createdAt type seen reply")
        .then(notifications => {
            Notification.updateMany(findQuery, { seen: true })
            .skip(skipDocs)
            .limit(maxLimit)
            .then(() => console.log('notification seen'));

            return res.status(200).json({ notifications });
        })
        .catch(err => {
            console.log(err.message);
            return res.status(500).json({ error: err.message });
        });
});

server.post("/all-notifications-count", verifyJWT, (req, res) => {
    let user_id = req.user; 

    let { filter } = req.body;

    let findQuery = { notification_for: user_id, user: { $ne: user_id } };

    if (filter != 'all') {
        findQuery.type = filter;
    }

    Notification.countDocuments(findQuery)
        .then(count => {
            return res.status(200).json({ totalDocs: count });
        })
        .catch(err => {
            return res.status(500).json({ error: err.message });
        });
});

server.post("/user-written-blogs", verifyJWT, (req, res) => {
  let user_id = req.user;

let { page, draft, query, deletedDocCount } = req.body;

let maxLimit = 5;
let skipDocs = (page - 1) * maxLimit;

if(deletedDocCount){
  skipDocs -= deletedDocCount;
}

Blog.find({ author: user_id, draft, title: new RegExp(query, 'i') })
.skip(skipDocs)
.limit(maxLimit)
.sort({ publishedAt: -1 })
.select(" title banner publishedAt blog_id activity des draft _id ")
.then(blogs => {
  return res.status(200).json({ blogs })
})
.catch(err => {
  return res.status(500).json({ error: err.message });
})

})

server.post("/user-written-blogs-count", verifyJWT, (req, res) => {

  let user_id = req.user;

  let { draft, query } = req.body;

  Blog.countDocuments({ author: user_id, draft, title: new RegExp(query, 'i') })
  .then(count => {
    return res.status(200).json({ totalDocs: count })
  })
  .catch(err => {
    console.log(err.message);
    return res.status(500).json({ error: err.message });
  })

})

server.post("/delete-blog", verifyJWT, (req, res) => {

  let user_id = req.user;
  let isAdmin = req.admin;

  let { blog_id } = req.body;


  if(isAdmin){
      Blog.findOneAndDelete({ blog_id })
    .then(blog => {

      Notification.deleteMany({ blog: blog._id }).then(data => console.log('notifications deleted'));

      Comment.deleteMany({ blog_id: blog._id }).then(data => console.log('comments deleted'));

      User.findOneAndUpdate({ _id: user_id }, { $pull: { blog: blog._id }, $inc: { "account_info.total_posts": -1 } })
        .then(user => console.log('Blog deleted'));

      return res.status(200).json({ status: 'done' });
    })
    .catch(err => {
      return res.status(500).json({ error: err.message })
    })
  }else {
  return res.status(500).json({ error: "you don't have permissions to delete the blog" });
}


})


//manage users 

// Add these routes to your server file

// Middleware to check if user is admin
const verifyAdmin = (req, res, next) => {
  if (!req.admin) {
    return res.status(403).json({ error: "Access denied. Admin only." });
  }
  next();
};

// Get all users (admin only)
server.get("/get-users", verifyJWT, verifyAdmin, (req, res) => {
  User.find({}, "personal_info.fullname personal_info.username personal_info.profile_img admin joinedAt")
    .sort({ joinedAt: -1 })
    .then((users) => {
      return res.status(200).json({ users });
    })
    .catch((err) => {
      return res.status(500).json({ error: err.message });
    });
});

// Toggle admin status (admin only)
server.post("/toggle-admin", verifyJWT, verifyAdmin, (req, res) => {
  const { userId } = req.body;
  const adminId = req.user; // The admin making the request

  // Prevent admin from removing their own admin status
  if (userId === adminId) {
    return res.status(400).json({ error: "You cannot modify your own admin status" });
  }

  User.findById(userId)
    .then((user) => {
      if (!user) {
        return res.status(404).json({ error: "User not found" });
      }

      // Toggle admin status
      user.admin = !user.admin;

      user
        .save()
        .then(() => {
          return res.status(200).json({
            message: user.admin
              ? "User granted admin access successfully"
              : "Admin access removed successfully",
            admin: user.admin,
          });
        })
        .catch((err) => {
          return res.status(500).json({ error: "Failed to update user role" });
        });
    })
    .catch((err) => {
      return res.status(500).json({ error: err.message });
    });
});




server.listen(PORT, () => {
  console.log("listening on port -> " + PORT);
});
