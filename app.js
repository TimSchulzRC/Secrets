require("dotenv").config();
const bodyParser = require("body-parser");
const express = require("express");
const ejs = require("ejs");
const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");

const saltRounds = 10;

const app = express();

app.use(express.static("public"));
app.set("view engine", "ejs");
app.use(
  bodyParser.urlencoded({
    extended: true,
  })
);

app.use(
  session({
    secrert: "this is top secret",
    resave: false,
    saveUninitialized: false,
  })
);
app.use(passport.initialize());
app.use(passport.session());

mongoose.connect("mongodb://localhost:27017/userDB", { useNewUrlParser: true });

const userSchema = new mongoose.Schema({
  email: String,
  password: String,
});

const User = new mongoose.model("User", userSchema);

app.get("/", (req, res) => {
  res.render("home");
});

app
  .route("/login")

  .get((req, res) => {
    res.render("login");
  })

  .post((req, res) => {
    const username = req.body.username;
    const password = req.body.password;

    User.findOne({ email: username }, function (err, foundUser) {
      if (err) {
        console.log(err);
      } else {
        if (foundUser) {
          bcrypt.compare(password, foundUser.password, function (err, result) {
            if (result == true) {
              res.render("secrets");
            } else {
              res.redirect("#");
            }
          });
        } else {
          res.redirect("#");
        }
      }
    });
  });

app.get("/logout", (req, res) => {
  res.redirect("/");
});

app
  .route("/register")

  .get((req, res) => {
    res.render("register");
  })

  .post((req, res) => {
    username = req.body.username;
    User.exists({ email: username }, function (err, exists) {
      if (!err) {
        if (!exists) {
          bcrypt.hash(req.body.password, saltRounds, function (err, hash) {
            const newUser = new User({
              email: req.body.username,
              password: hash,
            });
            newUser.save((err) => {
              if (err) {
                console.log(err);
              } else {
                res.render("secrets");
              }
            });
          });
        } else {
          res.redirect("#");
        }
      } else {
        console.log(err);
      }
    });
  });

app.listen(3000, () => {
  console.log("Server running on port localhost:3000");
});
