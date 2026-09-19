const express = require("express");
const mongoose = require("mongoose");
const dotenv = require("dotenv");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const helmet = require("helmet");
const { rateLimit } = require("express-rate-limit");

const User = require("./User");
const Post = require("./Post");

dotenv.config();

const app = express();

const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET;

const JWT_ISSUER = "connectsphere-api";
const JWT_AUDIENCE = "connectsphere-users";

// --------------------------------------------------
// SECURITY CHECKS
// --------------------------------------------------

if (!JWT_SECRET || JWT_SECRET.length < 32) {
  console.error(
    "ERROR: JWT_SECRET must exist in .env and should be at least 32 characters long.",
  );
  process.exit(1);
}

// --------------------------------------------------
// SECURITY MIDDLEWARE
// --------------------------------------------------

app.set("trust proxy", 1);

// Security headers
app.use(
  helmet({
    crossOriginResourcePolicy: {
      policy: "cross-origin",
    },
  }),
);

// JSON body size limit
app.use(express.json({ limit: "100kb" }));

// --------------------------------------------------
// CORS
// --------------------------------------------------

const allowedOrigins = [
  "http://127.0.0.1:5500",
  "http://localhost:5500",
  "https://connectsphere-web.onrender.com"
];
  .split(",")
  .map((origin) => origin.trim())
  .filter(Boolean);

app.use(
  cors({
    origin: function (origin, callback) {
      // Allow requests without an Origin header
      // such as Postman/server-to-server requests.
      if (!origin) {
        return callback(null, true);
      }

      if (allowedOrigins.includes(origin)) {
        return callback(null, true);
      }

      return callback(new Error("Origin not allowed by CORS"));
    },
    methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"],
    credentials: false,
  }),
);

// --------------------------------------------------
// RATE LIMITING
// --------------------------------------------------

// General API protection
const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 300,
  standardHeaders: "draft-8",
  legacyHeaders: false,
  message: {
    message: "Too many requests. Please try again later.",
  },
});

// Stronger protection for authentication endpoints
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 10,
  standardHeaders: "draft-8",
  legacyHeaders: false,
  message: {
    message: "Too many login or registration attempts. Please try again later.",
  },
});

app.use("/api", apiLimiter);

// --------------------------------------------------
// DATABASE CONNECTION
// --------------------------------------------------

mongoose
  .connect(process.env.MONGODB_URI)
  .then(() => {
    console.log("MongoDB connected successfully");
    console.log("Database:", mongoose.connection.name);
  })
  .catch((error) => {
    console.error("MongoDB connection error:", error);
    process.exit(1);
  });

// --------------------------------------------------
// HELPER FUNCTIONS
// --------------------------------------------------

function isValidObjectId(id) {
  return mongoose.Types.ObjectId.isValid(id);
}

function isValidEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

function isValidUsername(username) {
  return /^[a-zA-Z0-9_]{3,30}$/.test(username);
}

function isValidPassword(password) {
  return (
    typeof password === "string" &&
    password.length >= 8 &&
    password.length <= 128
  );
}

function createToken(user) {
  return jwt.sign(
    {
      id: user._id.toString(),
      username: user.username,
    },
    JWT_SECRET,
    {
      expiresIn: "7d",
      issuer: JWT_ISSUER,
      audience: JWT_AUDIENCE,
    },
  );
}

function safeUser(user) {
  return {
    id: user._id,
    username: user.username,
    name: user.name,
    email: user.email,
    bio: user.bio || "",
    profileImage: user.profileImage || "",
    followers: user.followers || [],
    following: user.following || [],
    createdAt: user.createdAt,
  };
}

// --------------------------------------------------
// JWT AUTHENTICATION MIDDLEWARE
// --------------------------------------------------

function authenticateToken(req, res, next) {
  const authHeader = req.headers.authorization;

  if (!authHeader) {
    return res.status(401).json({
      message: "Authentication required.",
    });
  }

  const parts = authHeader.split(" ");

  if (parts.length !== 2 || parts[0] !== "Bearer") {
    return res.status(401).json({
      message: "Invalid authorization format.",
    });
  }

  const token = parts[1];

  try {
    const decoded = jwt.verify(token, JWT_SECRET, {
      issuer: JWT_ISSUER,
      audience: JWT_AUDIENCE,
    });

    if (!decoded.id || !isValidObjectId(decoded.id)) {
      return res.status(401).json({
        message: "Invalid authentication token.",
      });
    }

    req.user = decoded;

    next();
  } catch (error) {
    if (error.name === "TokenExpiredError") {
      return res.status(401).json({
        message: "Session expired. Please login again.",
      });
    }

    return res.status(401).json({
      message: "Invalid authentication token.",
    });
  }
}

// --------------------------------------------------
// HOME
// --------------------------------------------------

app.get("/", (req, res) => {
  res.json({
    message: "ConnectSphere API is running",
  });
});

// --------------------------------------------------
// REGISTER
// --------------------------------------------------

app.post("/api/auth/register", authLimiter, async (req, res) => {
  try {
    let { username, name, email, password } = req.body;

    username = typeof username === "string" ? username.trim() : "";

    name = typeof name === "string" ? name.trim() : "";

    email = typeof email === "string" ? email.trim().toLowerCase() : "";

    if (!username || !name || !email || !password) {
      return res.status(400).json({
        message: "All fields are required.",
      });
    }

    if (!isValidUsername(username)) {
      return res.status(400).json({
        message:
          "Username must be 3-30 characters and contain only letters, numbers, and underscores.",
      });
    }

    if (name.length < 2 || name.length > 100) {
      return res.status(400).json({
        message: "Name must be between 2 and 100 characters.",
      });
    }

    if (!isValidEmail(email)) {
      return res.status(400).json({
        message: "Please enter a valid email address.",
      });
    }

    if (!isValidPassword(password)) {
      return res.status(400).json({
        message: "Password must be between 8 and 128 characters.",
      });
    }

    const existingUser = await User.findOne({
      $or: [{ username: username }, { email: email }],
    });

    if (existingUser) {
      if (existingUser.username === username) {
        return res.status(409).json({
          message: "Username already exists.",
        });
      }

      return res.status(409).json({
        message: "Email already registered.",
      });
    }

    const hashedPassword = await bcrypt.hash(password, 12);

    const user = await User.create({
      username,
      name,
      email,
      password: hashedPassword,
    });

    const token = createToken(user);

    res.status(201).json({
      message: "Registration successful.",
      token,
      user: safeUser(user),
    });
  } catch (error) {
    console.error("Register error:", error);

    res.status(500).json({
      message: "Server error.",
    });
  }
});

// --------------------------------------------------
// LOGIN
// --------------------------------------------------

app.post("/api/auth/login", authLimiter, async (req, res) => {
  try {
    let { email, password } = req.body;

    email = typeof email === "string" ? email.trim().toLowerCase() : "";

    if (!email || !password) {
      return res.status(400).json({
        message: "Email and password are required.",
      });
    }

    if (!isValidEmail(email)) {
      return res.status(400).json({
        message: "Please enter a valid email address.",
      });
    }

    const user = await User.findOne({
      email: email,
    });

    if (!user) {
      return res.status(401).json({
        message: "Invalid email or password.",
      });
    }

    const passwordMatch = await bcrypt.compare(password, user.password);

    if (!passwordMatch) {
      return res.status(401).json({
        message: "Invalid email or password.",
      });
    }

    const token = createToken(user);

    res.status(200).json({
      message: "Login successful.",
      token,
      user: safeUser(user),
    });
  } catch (error) {
    console.error("Login error:", error);

    res.status(500).json({
      message: "Server error.",
    });
  }
});

// --------------------------------------------------
// SEARCH USERS
// --------------------------------------------------

app.get("/api/users/search/:query", authenticateToken, async (req, res) => {
  try {
    const query =
      typeof req.params.query === "string" ? req.params.query.trim() : "";

    if (!query) {
      return res.status(400).json({
        message: "Search query is required.",
      });
    }

    const users = await User.find({
      $or: [
        {
          username: {
            $regex: query,
            $options: "i",
          },
        },
        {
          name: {
            $regex: query,
            $options: "i",
          },
        },
      ],
    })
      .select("username name profileImage followers following")
      .limit(20);

    res.status(200).json({
      users,
    });
  } catch (error) {
    console.error("Search users error:", error);

    res.status(500).json({
      message: "Server error.",
    });
  }
});

// --------------------------------------------------
// GET PROFILE
// --------------------------------------------------

app.get("/api/users/:username", authenticateToken, async (req, res) => {
  try {
    const username =
      typeof req.params.username === "string" ? req.params.username.trim() : "";

    const user = await User.findOne({
      username,
    }).select("-password");

    if (!user) {
      return res.status(404).json({
        message: "User not found.",
      });
    }

    res.status(200).json({
      user,
    });
  } catch (error) {
    console.error("Get profile error:", error);

    res.status(500).json({
      message: "Server error.",
    });
  }
});

// --------------------------------------------------
// UPDATE OWN PROFILE
// --------------------------------------------------

app.put("/api/users/:username", authenticateToken, async (req, res) => {
  try {
    const username =
      typeof req.params.username === "string" ? req.params.username.trim() : "";

    if (req.user.username !== username) {
      return res.status(403).json({
        message: "You can only update your own profile.",
      });
    }

    const user = await User.findOne({
      username,
    });

    if (!user) {
      return res.status(404).json({
        message: "User not found.",
      });
    }

    const { name, bio, profileImage } = req.body;

    if (
      name !== undefined &&
      (typeof name !== "string" ||
        name.trim().length < 2 ||
        name.trim().length > 100)
    ) {
      return res.status(400).json({
        message: "Name must be between 2 and 100 characters.",
      });
    }

    if (bio !== undefined && (typeof bio !== "string" || bio.length > 500)) {
      return res.status(400).json({
        message: "Bio cannot exceed 500 characters.",
      });
    }

    if (
      profileImage !== undefined &&
      (typeof profileImage !== "string" || profileImage.length > 2000)
    ) {
      return res.status(400).json({
        message: "Profile image URL is too long.",
      });
    }

    if (name !== undefined) {
      user.name = name.trim();
    }

    if (bio !== undefined) {
      user.bio = bio.trim();
    }

    if (profileImage !== undefined) {
      user.profileImage = profileImage.trim();
    }

    await user.save();

    res.status(200).json({
      message: "Profile updated successfully.",
      user: safeUser(user),
    });
  } catch (error) {
    console.error("Update profile error:", error);

    res.status(500).json({
      message: "Server error.",
    });
  }
});

// --------------------------------------------------
// CREATE POST
// --------------------------------------------------

app.post("/api/posts", authenticateToken, async (req, res) => {
  try {
    const { content, image } = req.body;

    if (typeof content !== "string" || !content.trim()) {
      return res.status(400).json({
        message: "Post content is required.",
      });
    }

    if (content.trim().length > 5000) {
      return res.status(400).json({
        message: "Post content cannot exceed 5000 characters.",
      });
    }

    if (
      image !== undefined &&
      (typeof image !== "string" || image.length > 5000)
    ) {
      return res.status(400).json({
        message: "Image URL is too long.",
      });
    }

    const user = await User.findById(req.user.id);

    if (!user) {
      return res.status(401).json({
        message: "User no longer exists.",
      });
    }

    const post = await Post.create({
      author: user._id,
      content: content.trim(),
      image: typeof image === "string" ? image.trim() : "",
    });

    const populatedPost = await Post.findById(post._id).populate(
      "author",
      "username name profileImage",
    );

    res.status(201).json({
      message: "Post created successfully.",
      post: populatedPost,
    });
  } catch (error) {
    console.error("Create post error:", error);

    res.status(500).json({
      message: "Server error.",
    });
  }
});

// --------------------------------------------------
// DELETE POST
// --------------------------------------------------

app.delete("/api/posts/:id", authenticateToken, async (req, res) => {
  try {
    const postId = req.params.id;

    if (!isValidObjectId(postId)) {
      return res.status(400).json({
        message: "Invalid post ID.",
      });
    }

    const post = await Post.findById(postId);

    if (!post) {
      return res.status(404).json({
        message: "Post not found.",
      });
    }

    if (post.author.toString() !== req.user.id) {
      return res.status(403).json({
        message: "You can only delete your own posts.",
      });
    }

    await Post.findByIdAndDelete(postId);

    res.status(200).json({
      message: "Post deleted successfully.",
    });
  } catch (error) {
    console.error("Delete post error:", error);

    res.status(500).json({
      message: "Server error.",
    });
  }
});

// --------------------------------------------------
// EDIT POST
// --------------------------------------------------

app.put("/api/posts/:id", authenticateToken, async (req, res) => {
  try {
    const postId = req.params.id;

    if (!isValidObjectId(postId)) {
      return res.status(400).json({
        message: "Invalid post ID.",
      });
    }

    const { content, image } = req.body;

    if (typeof content !== "string" || !content.trim()) {
      return res.status(400).json({
        message: "Post content is required.",
      });
    }

    if (content.trim().length > 5000) {
      return res.status(400).json({
        message: "Post content cannot exceed 5000 characters.",
      });
    }

    const post = await Post.findById(postId);

    if (!post) {
      return res.status(404).json({
        message: "Post not found.",
      });
    }

    if (post.author.toString() !== req.user.id) {
      return res.status(403).json({
        message: "You can only edit your own posts.",
      });
    }

    post.content = content.trim();

    if (image !== undefined) {
      if (typeof image !== "string" || image.length > 5000) {
        return res.status(400).json({
          message: "Image URL is too long.",
        });
      }

      post.image = image.trim();
    }

    await post.save();

    const updatedPost = await Post.findById(post._id).populate(
      "author",
      "username name profileImage",
    );

    res.status(200).json({
      message: "Post updated successfully.",
      post: updatedPost,
    });
  } catch (error) {
    console.error("Edit post error:", error);

    res.status(500).json({
      message: "Server error.",
    });
  }
});

// --------------------------------------------------
// GET POSTS
// --------------------------------------------------

app.get("/api/posts", authenticateToken, async (req, res) => {
  try {
    const posts = await Post.find()
      .populate("author", "username name profileImage")
      .populate("comments.user", "username name profileImage")
      .sort({
        createdAt: -1,
      })
      .limit(100);

    res.status(200).json({
      posts,
    });
  } catch (error) {
    console.error("Get posts error:", error);

    res.status(500).json({
      message: "Server error.",
    });
  }
});

// --------------------------------------------------
// LIKE POST
// --------------------------------------------------

app.post("/api/posts/:id/like", authenticateToken, async (req, res) => {
  try {
    const postId = req.params.id;

    if (!isValidObjectId(postId)) {
      return res.status(400).json({
        message: "Invalid post ID.",
      });
    }

    const post = await Post.findById(postId);

    if (!post) {
      return res.status(404).json({
        message: "Post not found.",
      });
    }

    const alreadyLiked = post.likes.some((id) => id.toString() === req.user.id);

    if (!alreadyLiked) {
      post.likes.push(req.user.id);
      await post.save();
    }

    res.status(200).json({
      message: "Post liked.",
      likes: post.likes,
    });
  } catch (error) {
    console.error("Like post error:", error);

    res.status(500).json({
      message: "Server error.",
    });
  }
});

// --------------------------------------------------
// UNLIKE POST
// --------------------------------------------------

app.post("/api/posts/:id/unlike", authenticateToken, async (req, res) => {
  try {
    const postId = req.params.id;

    if (!isValidObjectId(postId)) {
      return res.status(400).json({
        message: "Invalid post ID.",
      });
    }

    const post = await Post.findById(postId);

    if (!post) {
      return res.status(404).json({
        message: "Post not found.",
      });
    }

    post.likes = post.likes.filter((id) => id.toString() !== req.user.id);

    await post.save();

    res.status(200).json({
      message: "Post unliked.",
      likes: post.likes,
    });
  } catch (error) {
    console.error("Unlike post error:", error);

    res.status(500).json({
      message: "Server error.",
    });
  }
});

// --------------------------------------------------
// ADD COMMENT
// --------------------------------------------------

app.post("/api/posts/:id/comment", authenticateToken, async (req, res) => {
  try {
    const postId = req.params.id;

    if (!isValidObjectId(postId)) {
      return res.status(400).json({
        message: "Invalid post ID.",
      });
    }

    const { text } = req.body;

    if (typeof text !== "string" || !text.trim()) {
      return res.status(400).json({
        message: "Comment text is required.",
      });
    }

    if (text.trim().length > 1000) {
      return res.status(400).json({
        message: "Comment cannot exceed 1000 characters.",
      });
    }

    const post = await Post.findById(postId);

    if (!post) {
      return res.status(404).json({
        message: "Post not found.",
      });
    }

    post.comments.push({
      user: req.user.id,
      text: text.trim(),
    });

    await post.save();

    const updatedPost = await Post.findById(post._id).populate(
      "comments.user",
      "username name profileImage",
    );

    const newComment = updatedPost.comments[updatedPost.comments.length - 1];

    res.status(201).json({
      message: "Comment added successfully.",
      comment: newComment,
    });
  } catch (error) {
    console.error("Add comment error:", error);

    res.status(500).json({
      message: "Server error.",
    });
  }
});

// --------------------------------------------------
// FOLLOW USER
// --------------------------------------------------

app.post("/api/users/:username/follow", authenticateToken, async (req, res) => {
  try {
    const username =
      typeof req.params.username === "string" ? req.params.username.trim() : "";

    if (username === req.user.username) {
      return res.status(400).json({
        message: "You cannot follow yourself.",
      });
    }

    const targetUser = await User.findOne({
      username,
    });

    if (!targetUser) {
      return res.status(404).json({
        message: "User not found.",
      });
    }

    const currentUser = await User.findById(req.user.id);

    if (!currentUser) {
      return res.status(401).json({
        message: "User not found.",
      });
    }

    const alreadyFollowing = currentUser.following.some(
      (id) => id.toString() === targetUser._id.toString(),
    );

    if (!alreadyFollowing) {
      currentUser.following.push(targetUser._id);

      targetUser.followers.push(currentUser._id);

      await currentUser.save();
      await targetUser.save();
    }

    res.status(200).json({
      message: "User followed successfully.",
      following: currentUser.following,
      followers: targetUser.followers,
    });
  } catch (error) {
    console.error("Follow user error:", error);

    res.status(500).json({
      message: "Server error.",
    });
  }
});

// --------------------------------------------------
// UNFOLLOW USER
// --------------------------------------------------

app.post(
  "/api/users/:username/unfollow",
  authenticateToken,
  async (req, res) => {
    try {
      const username =
        typeof req.params.username === "string"
          ? req.params.username.trim()
          : "";

      if (username === req.user.username) {
        return res.status(400).json({
          message: "You cannot unfollow yourself.",
        });
      }

      const targetUser = await User.findOne({
        username,
      });

      if (!targetUser) {
        return res.status(404).json({
          message: "User not found.",
        });
      }

      const currentUser = await User.findById(req.user.id);

      if (!currentUser) {
        return res.status(401).json({
          message: "User not found.",
        });
      }

      currentUser.following = currentUser.following.filter(
        (id) => id.toString() !== targetUser._id.toString(),
      );

      targetUser.followers = targetUser.followers.filter(
        (id) => id.toString() !== currentUser._id.toString(),
      );

      await currentUser.save();
      await targetUser.save();

      res.status(200).json({
        message: "User unfollowed successfully.",
        following: currentUser.following,
        followers: targetUser.followers,
      });
    } catch (error) {
      console.error("Unfollow user error:", error);

      res.status(500).json({
        message: "Server error.",
      });
    }
  },
);

// --------------------------------------------------
// 404 HANDLER
// --------------------------------------------------

app.use((req, res) => {
  res.status(404).json({
    message: "API endpoint not found.",
  });
});

// --------------------------------------------------
// GLOBAL ERROR HANDLER
// --------------------------------------------------

app.use((error, req, res, next) => {
  console.error("Unhandled server error:", error);

  if (error.message === "Origin not allowed by CORS") {
    return res.status(403).json({
      message: "Request origin is not allowed.",
    });
  }

  if (error.type === "entity.too.large") {
    return res.status(413).json({
      message: "Request body is too large.",
    });
  }

  res.status(500).json({
    message: "Internal server error.",
  });
});

// --------------------------------------------------
// START SERVER
// --------------------------------------------------

app.listen(PORT, () => {
  console.log("ConnectSphere server running on http://localhost:" + PORT);
});
