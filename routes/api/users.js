const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const auth = require("../../middlewares/auth");
const schemaValidate = require("../../middlewares/schemaValidate");
const User = require("../../models/usersSchema");
const validationSchemas = require("../../validationSchemas/users");
const gravatar = require("gravatar");
const multer = require("multer");
const path = require("path");
const fs = require("fs").promises;
const jimp = require("jimp");

const uploadDir = path.join(__dirname, "../../tmp");
const storeImage = path.join(__dirname, "../../public/avatars");

const router = express.Router();
const storage = multer.diskStorage({
  destination: (req, res, cb) => {
    cb(null, uploadDir);
  },
  filename: (req, file, cb) => {
    const newFilename = `${new Date().getTime()}_${file.originalname}`;
    cb(null, newFilename);
  },
  limits: {
    fileSize: 1048576,
  },
});

const upload = multer({
  storage: storage,
});

router.post(
  "/signup",
  schemaValidate(validationSchemas.auth),
  async (req, res, next) => {
    try {
      const existingUser = await User.findOne({ email: req.body.email });
      if (existingUser) {
        res.status(409).json({
          message: "Email in use",
        });
        return;
      }

      if (req.file) {
        const newFilepath = path.join(storeImage, req.file.filename);
        await fs.rename(req.file.path, newFilepath);
      } else {
        console.log("No file provided");
      }

      const hashedPassword = await bcrypt.hash(req.body.password, 12);
      const newUser = await User.create({
        email: req.body.email,
        password: hashedPassword,
        avatarURL: gravatar.url(req.body.email),
      });

      res.status(201).json({
        user: {
          email: newUser.email,
          subscription: newUser.subscription,
          avatarURL: newUser.avatarURL,
        },
      });
    } catch (error) {
      next(error);
    }
  }
);

router.post(
  "/login",
  schemaValidate(validationSchemas.auth),
  async (req, res, next) => {
    try {
      const existingUser = await User.findOne({ email: req.body.email });
      if (
        !existingUser ||
        !(await bcrypt.compare(req.body.password, existingUser.password))
      ) {
        res.status(401).json({
          message: "Email or password is wrong",
        });
        return;
      }

      const payload = {
        _id: existingUser._id,
      };
      const jwtToken = jwt.sign(payload, process.env.JWT_SECRET, {
        expiresIn: "7d",
      });

      res.json({
        token: jwtToken,
        user: {
          email: existingUser.email,
          subscription: existingUser.subscription,
        },
      });
    } catch (error) {
      next(error);
    }
  }
);

router.get("/current", auth, async (req, res, next) => {
  try {
    res.json({
      email: req.user.email,
      subscription: req.user.subscription,
    });
  } catch (error) {
    next(error);
  }
});

router.patch("/avatars", auth, upload.single("avatar"), async (req, res) => {
  try {
    const avatar = await jimp.read(req.file.path);
    await avatar.resize(250, 250).writeAsync(req.file.path);
    const newPath = path.join(storeImage, req.file.filename);
    await fs.rename(req.file.path, newPath);
    const newUser = await User.findByIdAndUpdate(
      req.user._id,
      {
        avatarURL: `/avatars/${req.file.filename}`,
      },
      { new: true }
    );

    res.json({
      avatarURL: `${newUser.avatarURL}`,
    });
  } catch (error) {
    res.status(500).send({ message: "error" });
    console.log(error);
  }
});

module.exports = router;
