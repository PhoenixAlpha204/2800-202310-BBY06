require("./utils.js");
  
require("dotenv").config();
const express = require("express");
const MongoStore = require("connect-mongo");
const bcrypt = require("bcrypt");
const crypto = require("crypto");
const saltRounds = 12;

const session = require("express-session");

const app = express();

const Joi = require("joi");

const port = process.env.PORT || 3000;

const expireTime = 60 * 60 * 1000;

const mongodb_host = process.env.MONGODB_HOST;
const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;
const mongodb_database = process.env.MONGODB_DATABASE;
const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;
const node_session_secret = process.env.NODE_SESSION_SECRET;

const ObjectId = require("mongodb").ObjectId;
const songgestions_email = process.env.SONGGESTIONS_SUPPORT_EMAIL;
const songgestions_password = process.env.SONGGESTIONS_SUPPORT_PASSWORD;

var { database } = include("databaseConnection");
const userCollection = database.db(mongodb_database).collection("users");

const navLinks = [
    {name: "Recommendations", link: "/recommendationsTuning"},
    {name: "Browse", link: "/search"},
    {name: "Favourites", link: "/favourites"},
    {name: "Playlists", link: "/playlists"},
];
const url = require("url");
app.use("/", (req, res, next) => {
    app.locals.navLinks = navLinks;
    app.locals.currentUrl = url.parse(req.url).pathname;
    next();
});

app.set("view engine", "ejs");

app.use(express.urlencoded({ extended: false }));

var mongoStore = MongoStore.create({
  mongoUrl: `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/test`,
  crypto: {
    secret: mongodb_session_secret,
  },
});

app.use(
  session({
    secret: node_session_secret,
    store: mongoStore,
    saveUninitialized: false,
    resave: true,
  })
);

function isAuthenticated(req, res, next) {
  if (req.session.authenticated) {
    console.log("logged in");
    res.redirect("/loggedin");
  } else {
    next();
  }
};

function sessionValidation(req, res, next) {
  if (req.session.authenticated) {
    next();
  } else {
    console.log("not logged in");
    res.redirect('/login');
  }
}

function adminAuthorization(req, res, next) {
  if (req.session.user_type != "admin") {
    res.status(403);
    res.render("errorMessage", { error: "Not Authorized" });
    return;
  } else {
    next();
  }
}

app.get("/", isAuthenticated, (req, res) => {
  if (req.session.authenticated) {
    res.redirect("/loggedin");
  }
  res.render("index");
});

app.get("/createUser", (req, res) => {
  const errorMessage = req.query.errorMessage || "";
  res.render("createUser", { errorMessage: errorMessage });
});

app.get("/login", (req, res) => {
  const errorMessage = req.query.errorMessage || "";
  res.render("login", { errorMessage: errorMessage });
});

app.get("/profileUser", (req, res) => {
  if (!req.session.authenticated) {
    res.redirect("/");
  } else {
  res.render("profileUser");
  }
});

app.get("/login", (req, res) => {
  const errorMessage = req.query.errorMessage || "";
  res.render("login", { errorMessage: errorMessage });
});

// Submitting a new user
app.post("/submitUser", async (req, res) => {
  var securityQuestion = req.body.securityQuestion;
  var securityAnswer = req.body.securityAnswer;
  var username = req.body.username.toLowerCase();
  var password = req.body.password;
  var email = req.body.email;
  var securityQuestion = req.body.securityQuestion;
  var securityAnswer = req.body.securityAnswer;
  var errorMessage = "";

  const schema = Joi.object({
    username: Joi.string().alphanum().max(20).required(),
    email: Joi.string().email().required(),
    password: Joi.string().max(20).required(),
    securityAnswer: Joi.string().max(20).required(),
  });

  const validationResult = schema.validate({ username, email, password, securityAnswer });
  if (validationResult.error != null) {
    console.log(validationResult.error);
    errorMessage = "Invalid input. Please try again.";
    res.redirect("/createUser?errorMessage=" + encodeURIComponent(errorMessage));
    return;
  }

  const existingUser = await userCollection.findOne({ username: username });
  if (existingUser) {
    errorMessage = "Username already exists";
    console.log("Username already exists");
    res.redirect("/createUser?errorMessage=" + encodeURIComponent(errorMessage));
    return;
  }

  const existingEmail = await userCollection.findOne({ email: email });
  if (existingEmail) {
    errorMessage = "Email already exists";
    console.log("Email already exists");
    res.redirect("/createUser?errorMessage=" + encodeURIComponent(errorMessage));
    return;
  }

  var hashedPassword = await bcrypt.hash(password, saltRounds);
  var hashedSecurityAnswer = await bcrypt.hash(securityAnswer, saltRounds);

  await userCollection.insertOne({
    username: username,
    email: email,
    password: hashedPassword,
    securityQuestion: securityQuestion,
    securityAnswer: hashedSecurityAnswer,
    user_type: "user",
  });
  console.log("Inserted user");

  req.session.authenticated = true;
  req.session.username = username;
  req.session.user_type = 'user';
  req.session.cookie.maxAge = expireTime;

  res.redirect("/loggedin");
});

// Logging in
app.post("/loggingin", async (req, res) => {
  var username = req.body.username.toLowerCase();
  var password = req.body.password;
  var errorMessage = "";

  const schema = Joi.string().max(20).required();
  const validationResult = schema.validate(username);
  if (validationResult.error != null) {
    console.log(validationResult.error);
    errorMessage = "Invalid input. Please try again.";
    res.redirect("/login?errorMessage=" + encodeURIComponent(errorMessage));
    return;
  }
  const result = await userCollection.find({ username: username }).project({ username: 1, password: 1, user_type: 1, _id: 1 }).toArray();

  console.log(result);
  if (result.length != 1) {
    console.log("user not found");
    errorMessage = "Username not found. Please try again.";
    res.redirect("/login?errorMessage=" + encodeURIComponent(errorMessage));
    return;
  }
  if (await bcrypt.compare(password, result[0].password)) {
    console.log("correct password");
    req.session.authenticated = true;
    req.session.username = username;
    req.session.user_type = result[0].user_type;
    req.session.cookie.maxAge = expireTime;

    req.session.save(() => {
      res.redirect("/loggedin");
    });
    return;
  } else {
    console.log("incorrect password");
    errorMessage = "Incorrect password. Did you forget your password? Click the \"Forgot Password\" button to reset it";
    res.redirect("/login?errorMessage=" + encodeURIComponent(errorMessage));
    return;
  }
});

app.get("/loggedin", sessionValidation, (req, res) => {
  var username = req.session.username;
  var template = "loggedin.ejs";
  var data = {
    username: username,
  };
  res.render(template, data);
});

app.get("/dataHistory", sessionValidation, async (req, res) => {
  const userLikesDislikes = await userCollection.find({ username: req.session.username }).project({ likes: 1, dislikes: 1, favourites: 1, _id: 1 }).toArray();
  if (userLikesDislikes[0].likes == null || userLikesDislikes[0].dislikes == null || userLikesDislikes[0].favourites == null) {
    initLikesDislikes(userLikesDislikes[0]);
  }
  var likes = [];
  var dislikes = [];
  const songCollection = database.db(mongodb_database).collection("kaggle");
  for (var i = 0; i < userLikesDislikes[0].likes.length; i++) {
    let res = await songCollection.findOne({ _id: userLikesDislikes[0].likes[i] });
    const uriParts = res.Uri.split(":");
    res.Uri = uriParts[2];
    likes.push(res);
  }
  for (var i = 0; i < userLikesDislikes[0].dislikes.length; i++) {
    let res = await songCollection.findOne({ _id: userLikesDislikes[0].dislikes[i] });
    const uriParts = res.Uri.split(":");
    res.Uri = uriParts[2];
    dislikes.push(res);
  }
  var script = require('./scripts/likesDislikes.js');
  res.render("dataHistory", { likes: likes, dislikes: dislikes, script: script, userLikesDislikes: userLikesDislikes[0] });
});

app.get("/userSettings", sessionValidation, (req, res) => {
  var username = req.session.username;
  var template = "userSettings.ejs";
  var data = {
    username: username,
  };
  res.render(template, data);
});

app.get("/favourites", sessionValidation, async (req, res) => {
  const userLikesDislikes = await userCollection.find({ username: req.session.username }).project({ likes: 1, dislikes: 1, favourites: 1, _id: 1 }).toArray();
  if (userLikesDislikes[0].likes == null || userLikesDislikes[0].dislikes == null || userLikesDislikes[0].favourites == null) {
    initLikesDislikes(userLikesDislikes[0]);
  }
  var favourites = [];
  const songCollection = database.db(mongodb_database).collection("kaggle");
  for (var i = 0; i < userLikesDislikes[0].favourites.length; i++) {
    let res = await songCollection.findOne({ _id: userLikesDislikes[0].favourites[i] });
    const uriParts = res.Uri.split(':');
    res.Uri = uriParts[2];
    favourites.push(res);
  }
  console.log(favourites);
  var script = require('./scripts/likesDislikes.js');
  res.render("favourites", { userLikesDislikes: userLikesDislikes[0], favourites: favourites, script: script });
});

app.get("/playlists", sessionValidation, (req, res) => {
  var username = req.session.username;
  var template = "playlists.ejs";
  var data = {
    username: username,
  };
  res.render(template, data);
});


app.get("/profile", sessionValidation, async (req, res) => {
  var username = req.session.username;
  const result = await userCollection
    .find({ username: username })
    .project({ username: 1, email: 1, securityQuestion: 1, _id: 1 })
    .toArray();
  console.log(result);
  if (result.length != 1) {
    console.log("user not found");
    res.redirect("/loginErrorUser");
    return;
  } else {
    const user = result[0];
    res.render("profile", {
      username: username,
      email: user.email,
      securityQuestion: user.securityQuestion,
    });
    return;
  }
});

app.get("/profileUser", sessionValidation, async (req, res) => {
  var username = req.session.username;
  const result = await userCollection
    .find({ username: username })
    .project({ username: 1, email: 1, securityQuestion: 1, _id: 1 })
    .toArray();
  console.log(result);
  if (result.length != 1) {
    console.log("user not found");
    res.redirect("/loginErrorUser");
    return;
  } else {
    const user = result[0];
    res.render("profileUser", {
      username: username,
      email: user.email,
      securityQuestion: user.securityQuestion,
    });
    return;
  }
});

app.get("/forgotPassword", (req, res) => {
  const errorMessage = req.query.errorMessage || "";
  res.render("forgotPassword", { errorMessage: errorMessage });
});

app.get("/about", (req, res) => {
  res.render("about");
});

app.get("/contact", (req, res) => {
  var missingEmail = req.query.missing;
  res.render("contact", { missing: missingEmail });
});

app.post("/email", (req, res) => {
  var email = req.body.email;
  if (!email) {
    res.redirect("/contact?missing=1");
  } else {
    res.send("The email you input is: " + email);
  }
});

app.post("/submitEmail", (req, res) => {
  var email = req.body.email;
  if (!email) {
    res.redirect("/contact?missing=1");
  } else {
    res.render("submitEmail", { email: email });
  }
});

app.post("/checkEmail", async (req, res) => {
  var email = req.body.email;
  let errorMessage = ""; // Declare and initialize the errorMessage variable

  const result = await userCollection
    .find({ email: email })
    .project({ username: 1, securityQuestion: 1, _id: 1 })
    .toArray();
  console.log(result);
  if (result.length != 1) {
    errorMessage = "Email not found. Please try again.";
    console.log("user not found");
    res.redirect("/forgotPassword?errorMessage=" + encodeURIComponent(errorMessage));
    return;
  } else {
    const token = crypto.randomBytes(20).toString("hex");
    const expireTime = Date.now() + 1 * 60 * 60 * 1000; // 1 hour
    await userCollection.updateOne(
      { email: email },
      { $set: { resetPasswordToken: token, resetPasswordExpires: expireTime } }
    );
    console.log("token: " + token);

    res.render("securityQuestion", {
      email: email,
      securityQuestion: result[0].securityQuestion,
      token: token,
      errorMessage: errorMessage // Pass the errorMessage variable to the res.render() method
    });
  }
});


app.get("/securityQuestion", (req, res) => {
  const errorMessage = req.query.errorMessage || "";  
  const securityQuestion = req.query.securityQuestion || ""; // Retrieve securityQuestion from query parameter if needed
  res.render("securityQuestion", { errorMessage: errorMessage, securityQuestion: securityQuestion });
});

app.get("/securityQuestionError", (req, res) => {
  res.render("securityQuestionError");
});

app.get("/resetPassword", (req, res) => {
  res.render("resetPassword");
});

app.get("/resetPasswordError", (req, res) => {
  res.render("resetPasswordError");
});

app.post('/resetPassword', async (req, res) => {
  var email = req.body.email;
  var newPass = req.body.newPassword;
  var confirmPass = req.body.confirmPassword;

  const result = await userCollection.find({ email: email }).project({ username: 1, resetPasswordExpires: 1, resetPasswordToken: 1, _id: 1 }).toArray();
  if (newPass == null || confirmPass == null) {
    res.redirect("/resetPasswordError");
    console.log("password not entered");
    return;
  }
  if (result.length != 1) {
    console.log("user not found");
    res.redirect("/resetPasswordError");
    console.log("user not found");
    return;
  } else {
    const user = result[0];
    if (newPass !== confirmPass) {
      console.log("passwords do not match");
      res.redirect("/resetPasswordError");
      console.log("passwords do not match");
      return;
    } else {
      console.log("passwords match");
      var hashedPassword = await bcrypt.hash(newPass, saltRounds);
      await userCollection.updateOne({ email: email }, { $set: { password: hashedPassword } });
      console.log("password updated");
      res.redirect("/login");
      return;
    }
  }
});

app.post('/checkSecurityQuestion', async (req, res) => {
  var email = req.body.email;
  var securityAnswer = req.body.securityAnswer;
  var token = req.body.token;

  const result = await userCollection
      .find({ email: email })
      .project({ username: 1, securityAnswer: 1, resetPasswordExpires: 1, resetPasswordToken: 1, _id: 1 })
      .toArray();
  console.log(result);

  if (securityAnswer == null) {
      res.redirect("/securityQuestionError");
      return;
  }
  if (result.length != 1) {
      console.log("user not found");
      res.redirect("/securityQuestionError");
      return;
  } else {
      const user = result[0];
      if (await bcrypt.compare(securityAnswer, user.securityAnswer)) {
          console.log("correct security answer");
          if (Date.now() > user.resetPasswordExpires) {
              console.log("token expired");
              res.redirect("/tokenExpired");
              return;
          } else {
              console.log("token not expired");
              res.render("resetPassword", { email: email, token: token });
              return;
          }
      } else {
          console.log("incorrect security answer");
          res.redirect("/securityQuestionError");
          return;
      }
  }
});


const nodemailer = require("nodemailer");
const { error } = require("console");

app.get("/logout", (req, res) => {
  req.session.destroy();
  res.redirect("/");
});

app.get("/admin", sessionValidation, adminAuthorization, async (req, res) => {
  if (!req.session.authenticated) {
    res.redirect("/login");
  }
  const result = await userCollection
    .find()
    .project({ username: 1, _id: 1 })
    .toArray();

  res.render("admin", { users: result });
});

app.post(
  "/adminUser",
  sessionValidation,
  adminAuthorization,
  async (req, res) => {
    const ObjectId = require("mongodb").ObjectId;
    const userId = req.body.userId;
    const userObjectId = new ObjectId(userId);
    await userCollection.updateOne(
      { _id: userObjectId },
      { $set: { user_type: "admin" } }
    );
    console.log(userId);
    res.redirect("/admin");
  }
);

app.post(
  "/unAdminUser",
  sessionValidation,
  adminAuthorization,
  async (req, res) => {
    const ObjectId = require("mongodb").ObjectId;
    const userId = req.body.userId;
    const userObjectId = new ObjectId(userId);
    await userCollection.updateOne(
      { _id: userObjectId },
      { $set: { user_type: "user" } }
    );
    console.log(userId);
    res.redirect("/admin");
  }
);

app.get("/search", sessionValidation, (req, res) => {
  res.render("search");
});

app.post("/searchSong", sessionValidation, async (req, res) => {
  const userLikesDislikes = await userCollection.find({ username: req.session.username }).project({ likes: 1, dislikes: 1, _id: 1 }).toArray();
  //if passed filters, filter previous results
  if (req.query.artist != undefined || req.query.album != undefined) {
    var list = [...req.session.searchResults];
    //filter by artist
    if (req.query.artist != undefined) {
      var artist = req.query.artist.replace(/_/g, ' ');
      artist = formatSearch(artist);
      for (var i = 0; i < list.length; i++) {
        var contains = false;
        var artists = formatSearch(list[i].Artist);
        artists.forEach((name) => {
          artist.forEach((term) => {
            if (name.match(new RegExp(term, 'g'))) {
              contains = true;
            }
          });
        });
        if (!contains) {
          list.splice(i, 1);
          i--;
        }
      }
    }
    //filter by album
    if (req.query.album != undefined) {
      var album = req.query.album.replace(/_/g, ' ');
      album = formatSearch(album);
      for (var i = 0; i < list.length; i++) {
        var albumName = formatSearch(list[i].Album);
        var contains = false;
        albumName.forEach((name) => {
          album.forEach((term) => {
            if (name.match(new RegExp(term, 'g'))) {
              contains = true;
            }
          });
        });
        if (!contains) {
          list.splice(i, 1);
          i--;
        }
      }
    }
    var script = require('./scripts/likesDislikes.js');
    res.render("results", { results: list, script: script, userLikesDislikes: userLikesDislikes[0]});
  //if no filters passed, get new results
  } else {
    const userLikesDislikes = await userCollection.find({ username: req.session.username }).project({ likes: 1, dislikes: 1, favourites: 1, _id: 1 }).toArray();
    if (userLikesDislikes[0].likes == null || userLikesDislikes[0].dislikes == null || userLikesDislikes[0].favourites == null) {
      initLikesDislikes(userLikesDislikes[0]);
    }
    var searchTerm;
    if (req.body.song != null) {
      searchTerm = req.body.song;
    } else {
      searchTerm = req.query.q;
    }
    const result = await userCollection.find({ username: req.session.username }).project({ searchHistory: 1, _id: 1 }).toArray();
    //update user's search history with the new search term
    if (result[0].searchHistory == null) {
      result[0].searchHistory = [];
    }
    if (result[0].searchHistory[0] != searchTerm) {
      result[0].searchHistory.unshift(searchTerm);
      if (result[0].searchHistory.length > 5) {
        result[0].searchHistory.pop();
      }
      console.log(result[0].searchHistory);
    }
    await userCollection.updateOne({ _id: result[0]._id }, { $set: { searchHistory: result[0].searchHistory } });
    searchTerm = formatSearch(searchTerm);
    const songCollection = database.db(mongodb_database).collection("kaggle");
    var list = await songCollection.find().project({ Track: 1, Artist: 1, Album: 1, Uri: 1}).toArray();
    //filter songs in the database based on the given name
    list.forEach((song) => {
      song.formattedName = formatSearch(song.Track);
      song.count = 0;
      const uriParts = song.Uri.split(":");
      song.Uri = uriParts[2];
    });
    var count = 0;
    list.forEach((song) => {
      song.formattedName.forEach((name) => {
        searchTerm.forEach((term) => {
          if (name.match(new RegExp(term, 'g'))) {
            count += term.length / name.length;
          }
        });
        song.count += count / song.formattedName.length;
        count = 0;
      });
    });
    list = list.sort(function (a, b) {
      return b.count - a.count;
    });
    for (var i = 0; i < list.length; i++) {
      if (list[i].count === 0) {
        list.splice(i, 1);
        i--;
      }
    }
    //log everything for future filtering
    req.session.searchTerm = searchTerm;
    req.session.searchResults = list;
    console.log(req.session.searchResults);
    var script = require('./scripts/likesDislikes.js');
    res.render("results", { results: list, script: script, userLikesDislikes: userLikesDislikes[0] });
  }
});

//this function sourced from: https://astromacguffin.com/ref/id/62dc488124d8b5752194eccd
function formatSearch(searchTerm) {
  return searchTerm
    .replace(/\(/gi, " ")
    .replace(/\)/gi, " ")
    .replace(/\./gi, " ")
    .replace(/!/gi, " ")
    .replace(/@/gi, " ")
    .replace(/#/gi, " ")
    .replace(/\$/gi, " ")
    .replace(/\%/gi, " ")
    .replace(/\^/gi, " ")
    .replace(/&/gi, " ")
    .replace(/\*/gi, " ")
    .replace(/-/gi, " ")
    .replace(/_/gi, " ")
    .replace(/=/gi, " ")
    .replace(/\+/gi, " ")
    .replace(/\{/gi, " ")
    .replace(/\[/gi, " ")
    .replace(/\}/gi, " ")
    .replace(/\]/gi, " ")
    .replace(/:/gi, " ")
    .replace(/;/gi, " ")
    .replace(/"/gi, " ")
    .replace(/'/gi, " ")
    .replace(/`/gi, " ")
    .replace(/,/gi, " ")
    .replace(/>/gi, " ")
    .replace(/</gi, " ")
    .replace(/\//gi, " ")
    .replace(/\?/gi, " ")
    .replace(/\|/gi, " ")
    .replace(/\\/gi, " ")
    .replace(/\n/gi, " ")
    .toLowerCase()
    .split(" ");
}

app.post("/searchHistory", async (req, res) => {
  const result = await userCollection
    .find({ username: req.session.username })
    .project({ searchHistory: 1, _id: 1 })
    .toArray();
  res.render("history", { searches: result[0].searchHistory });
});

app.get("/filters", function (req, res) {
  res.render("filters");
});

app.post("/submitFilters", function (req, res) {
  var artist = req.body.artist.replace(/ /g, '_');
  var album = req.body.album.replace(/ /g, '_');
  if (artist != "" || album != "") {
    res.redirect(307, `/searchSong?artist=${artist}&album=${album}`);
  } else {
    var searchTerm = req.session.searchTerm;
    res.redirect(307, `/searchSong?q=${searchTerm}`);
  }
});

app.get("/recommendationsTuning", sessionValidation, async function(req, res) {
    var script = require('./scripts/likesDislikes.js');
    var songs = [];
    const songCollection = database.db(mongodb_database).collection("kaggle");
    var collectionSize = await songCollection.count();
    var songIds = [undefined];
    var temp;
    const userLikesDislikes = await userCollection.find({ username: req.session.username }).project({ likes: 1, dislikes: 1, favourites: 1, _id: 1 }).toArray();
    if (userLikesDislikes[0].likes == null || userLikesDislikes[0].dislikes == null || userLikesDislikes[0].favourites == null) {
      initLikesDislikes(userLikesDislikes[0]);
    }
    for (let i = 0; i < 5; i++) {
        var counter = 0;
        while (songIds.includes(temp) || userLikesDislikes[0].likes.includes(temp) || userLikesDislikes[0].dislikes.includes(temp)) {
            temp = Math.floor(Math.random() * collectionSize);
            counter++;
            if (counter >= 100) {
                break;
            }
        }
        if (counter >= 100) {
            break;
        }
        songIds.push(temp);
        let res = await songCollection.findOne({ _id: temp });
        const uriParts = res.Uri.split(":");
        res.Uri = uriParts[2];
        songs.push(res);
        
    }
    res.render("recommendationsTuning", { script: script, songs: songs, userLikesDislikes: userLikesDislikes[0]});
});

async function initLikesDislikes(array) {
  if (array.likes == null) {
    array.likes = [];
  }
  if (array.dislikes == null) {
      array.dislikes = [];
  }
  if (array.favourites == null) {
    array.favourites = [];
  }
  await userCollection.updateOne({ _id: array._id }, { $set: { likes: array.likes, dislikes: array.dislikes, favourites: array.favourites } });
};

app.get('/like/:id', async (req, res) => {
    var userLikesDislikes = await userCollection.find({ username: req.session.username }).project({ likes: 1, dislikes: 1, _id: 1 }).toArray();
    userLikesDislikes = userLikesDislikes[0];
    var id = parseInt(req.params.id);
    if (userLikesDislikes.dislikes.includes(id)) {
        userLikesDislikes.dislikes.splice(userLikesDislikes.dislikes.indexOf(id), 1);
    }
    if (userLikesDislikes.likes.includes(id)) {
        userLikesDislikes.likes.splice(userLikesDislikes.likes.indexOf(id), 1);
    } else {
        userLikesDislikes.likes.push(id);
    }
    await userCollection.updateOne({ _id: userLikesDislikes._id }, { $set: { likes: userLikesDislikes.likes, dislikes: userLikesDislikes.dislikes } });
    res.send("" + id);
});

app.get('/dislike/:id', async (req, res) => {
    var userLikesDislikes = await userCollection.find({ username: req.session.username }).project({ likes: 1, dislikes: 1, _id: 1 }).toArray();
    userLikesDislikes = userLikesDislikes[0];
    var id = parseInt(req.params.id);
    if (userLikesDislikes.likes.includes(id)) {
        userLikesDislikes.likes.splice(userLikesDislikes.likes.indexOf(id), 1);
    }
    if (userLikesDislikes.dislikes.includes(id)) {
        userLikesDislikes.dislikes.splice(userLikesDislikes.dislikes.indexOf(id), 1);
    } else {
        userLikesDislikes.dislikes.push(id);
    }
    await userCollection.updateOne({ _id: userLikesDislikes._id }, { $set: { likes: userLikesDislikes.likes, dislikes: userLikesDislikes.dislikes } });
    res.send("" + id);
});

app.get('/favourite/:id', async (req, res) => {
  var userFavourites = await userCollection.find({ username: req.session.username }).project({ favourites: 1, _id: 1 }).toArray();
  userFavourites = userFavourites[0];
  var id = parseInt(req.params.id);
  if (userFavourites.favourites.includes(id)) {
      userFavourites.favourites.splice(userFavourites.favourites.indexOf(id), 1);
  } else {
      userFavourites.favourites.push(id);
  }
  await userCollection.updateOne({ _id: userFavourites._id }, { $set: { favourites: userFavourites.favourites } });
  res.send("" + id);
});

app.use(express.static(__dirname + "/public"));

app.get("*", (req, res) => {
  res.status(404);
  res.render("404");
});

app.listen(port, () => {
  console.log("Songgestions is listening on port " + port);
});
