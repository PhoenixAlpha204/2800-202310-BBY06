/*jshint esversion: 8, node: true */

require("./utils.js");

require("dotenv").config();
const express = require("express");
const axios = require("axios");
const MongoStore = require("connect-mongo");
const bcrypt = require("bcrypt");
const crypto = require("crypto");
const saltRounds = 12;
const url = require("url");

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

var { database } = include("databaseConnection");
const userCollection = database.db(mongodb_database).collection("users");
const songCollection = database.db(mongodb_database).collection("kaggle");

const navLinks = [
  { link: "/recommendationsTuning", name: "Recommendations" },
  { link: "/search", name: "Browse" },
  { link: "/favourites", name: "Favourites" },
  { link: "/playlists", name: "Playlists" }
];

var mongoStore = MongoStore.create({
  crypto: { secret: mongodb_session_secret },
  mongoUrl: `mongodb+srv://${mongodb_user}:` +
    `${mongodb_password}@${mongodb_host}/test`
});

app.use("/", function (req, res, next) {
  app.locals.navLinks = navLinks;
  app.locals.currentUrl = url.parse(req.url).pathname;
  next();
});

app.set("view engine", "ejs");

app.use(express.urlencoded({ extended: false }));

app.use(
  session({
    resave: true,
    saveUninitialized: false,
    secret: node_session_secret,
    store: mongoStore
  })
);

/**
 * Only allow user to proceed if they are logged in.
 * 
 * @param {*} req the request
 * @param {*} res the response
 * @param {*} next the page to proceed to
 */
function sessionValidation(req, res, next) {
  if (req.session.authenticated) {
    next();
  } else {
    console.log("not logged in");
    res.redirect("/login");
  }
}

app.get("/", function (req, res) {
  if (req.session.authenticated) {
    res.redirect("/loggedin");
  } else {
    res.render("index");
  }
});

app.get("/createUser", function (req, res) {
  const errorMessage = req.query.errorMessage || "";
  res.render("createUser", { errorMessage: errorMessage });
});

app.get("/login", function (req, res) {
  const errorMessage = req.query.errorMessage || "";
  res.render("login", { errorMessage: errorMessage });
});

app.get("/profileUser", function (req, res) {
  if (!req.session.authenticated) {
    res.redirect("/");
  } else {
    res.render("profileUser");
  }
});

app.get("/login", function (req, res) {
  const errorMessage = req.query.errorMessage || "";
  res.render("login", { errorMessage: errorMessage });
});

/**
 * Submits user registration data to the database.
 *
 * @param {*} req The HTTP request object containing the user registration data.
 * @param {*} res The HTTP response object for sending a response.
 */
app.post("/submitUser", async function (req, res) {
  var securityQuestion = req.body.securityQuestion;
  var securityAnswer = req.body.securityAnswer;
  var username = req.body.username.toLowerCase();
  var password = req.body.password;
  var email = req.body.email;
  var errorMessage = "";

  //encrypt password
  var hashedPassword = await bcrypt.hash(password, saltRounds);
  var hashedSecurityAnswer = await bcrypt.hash(
    securityAnswer, saltRounds);

  //validate input using Joi
  const schema = Joi.object({
    email: Joi.string().email().required(),
    password: Joi.string().max(20).required(),
    securityAnswer: Joi.string().max(20).required(),
    username: Joi.string().alphanum().max(20).required()
  });

  //provide error if input is invalid
  const validationResult = schema.validate({
    email, password, securityAnswer, username
  });
  if (validationResult.error != null) {
    console.log(validationResult.error);
    errorMessage = "Invalid input. Please try again.";
    res.redirect("/createUser?errorMessage=" +
      encodeURIComponent(errorMessage));
    return;
  }

  //provide error if username already exist in database
  const existingUser = await userCollection.findOne({ username: username });
  if (existingUser) {
    errorMessage = "Username already exists";
    console.log("Username already exists");
    res.redirect("/createUser?errorMessage=" +
      encodeURIComponent(errorMessage));
    return;
  }

  //provide error if email already exist in database
  const existingEmail = await userCollection.findOne({ email: email });
  if (existingEmail) {
    errorMessage = "Email already exists";
    console.log("Email already exists");
    res.redirect("/createUser?errorMessage=" +
      encodeURIComponent(errorMessage));
    return;
  }

  //add user to database and log them in
  await userCollection.insertOne({
    email: email,
    password: hashedPassword,
    securityAnswer: hashedSecurityAnswer,
    securityQuestion: securityQuestion,
    user_type: "user",
    username: username
  });

  req.session.authenticated = true;
  req.session.username = username;
  req.session.user_type = "user";
  req.session.cookie.maxAge = expireTime;
  res.redirect("/loggedin");
});

/**
 * Log user in if username and password match database.
 *
 * @param {*} req The HTTP request object containing the login data.
 * @param {*} res The HTTP response object for sending a response.
 */
app.post("/loggingin", async function (req, res) {
  var username = req.body.username.toLowerCase();
  var password = req.body.password;
  var errorMessage = "";

  //validate input using joi
  const schema = Joi.string().max(20).required();
  const validationResult = schema.validate(username);
  if (validationResult.error != null) {
    console.log(validationResult.error);
    errorMessage = "Invalid input. Please try again.";
    res.redirect("/login?errorMessage=" +
      encodeURIComponent(errorMessage));
    return;
  }

  //search database for given username
  const result = await userCollection.find({ username: username })
    .project({ password: 1, user_type: 1, username: 1, _id: 1 }).toArray();

  //return error if user not found
  if (result.length != 1) {
    console.log("user not found");
    errorMessage = "Username not found. Please try again.";
    res.redirect("/login?errorMessage=" +
      encodeURIComponent(errorMessage));
    return;
  }

  //validate password, log in user if correct
  if (await bcrypt.compare(password, result[0].password)) {
    req.session.authenticated = true;
    req.session.username = username;
    req.session.user_type = result[0].user_type;
    req.session.cookie.maxAge = expireTime;

    //redirect to appropriate page after session is saved
    req.session.save(function () {
      res.redirect("/loggedin");
    });
  } else {
    errorMessage = "Incorrect password. Did you forget your password?" +
      " Click the \"Forgot Password\" button to reset it";
    res.redirect("/login?errorMessage=" + encodeURIComponent(errorMessage));
  }
});

app.get("/loggedin", sessionValidation, function (req, res) {
  var username = req.session.username;
  var template = "loggedin.ejs";
  var data = {
    username: username,
  };
  res.render(template, data);
});

//view user's previous likes and dislikes
app.get("/dataHistory", sessionValidation, async function (req, res) {
  var likes = [];
  var dislikes = [];
  const userLikesDislikes = await userCollection
    .find({ username: req.session.username })
    .project({ _id: 1, dislikes: 1, favourites: 1, likes: 1 }).toArray();
  if (userLikesDislikes[0].likes == null ||
    userLikesDislikes[0].dislikes == null ||
    userLikesDislikes[0].favourites == null) {
    initLikesDislikes(userLikesDislikes[0]);
  }
  //create list of likes
  for (let i = 0; i < userLikesDislikes[0].likes.length; i++) {
    let response = await songCollection
      .findOne({ _id: userLikesDislikes[0].likes[i] });
    response.Uri = response.Uri.split(":")[2];
    likes.push(response);
  }
  //create list of dislikes
  for (let i = 0; i < userLikesDislikes[0].dislikes.length; i++) {
    let response = await songCollection
      .findOne({ _id: userLikesDislikes[0].dislikes[i] });
    response.Uri = response.Uri.split(":")[2];
    dislikes.push(response);
  }
  var script = require("./scripts/likesDislikes.js");
  res.render("dataHistory", {
    likes: likes, dislikes: dislikes,
    script: script, userLikesDislikes: userLikesDislikes[0]
  });
});

app.get("/userSettings", sessionValidation, function (req, res) {
  var username = req.session.username;
  var template = "userSettings.ejs";
  var data = {
    username: username,
  };
  res.render(template, data);
});

//view user's favourited songs
app.get("/favourites", sessionValidation, async function (req, res) {
  const userLikesDislikes = await userCollection
    .find({ username: req.session.username })
    .project({ likes: 1, dislikes: 1, favourites: 1, _id: 1 }).toArray();
  if (userLikesDislikes[0].likes == null ||
    userLikesDislikes[0].dislikes == null ||
    userLikesDislikes[0].favourites == null) {
    initLikesDislikes(userLikesDislikes[0]);
  }
  var favourites = [];
  //create list of favourites
  for (let i = 0; i < userLikesDislikes[0].favourites.length; i++) {
    let res = await songCollection
      .findOne({ _id: userLikesDislikes[0].favourites[i] });
    res.Uri = res.Uri.split(":")[2];
    favourites.push(res);
  }
  console.log(favourites);
  var script = require("./scripts/likesDislikes.js");
  res.render("favourites", {
    userLikesDislikes: userLikesDislikes[0],
    favourites: favourites, script: script
  });
});

app.get("/playlists", sessionValidation, function (req, res) {
  var username = req.session.username;
  var template = "playlists.ejs";
  var data = {
    username: username,
  };
  res.render(template, data);
});

// view user's profile information
app.get("/profile", sessionValidation, async function (req, res) {
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

// general profile page for users
app.get("/profileUser", sessionValidation, async function (req, res) {
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

app.get("/forgotPassword", function (req, res) {
  const errorMessage = req.query.errorMessage || "";
  res.render("forgotPassword", { errorMessage: errorMessage });
});

app.get("/about", function (req, res) {
  res.render("about");
});

app.get("/contact", function (req, res) {
  var missingEmail = req.query.missing;
  res.render("contact", { missing: missingEmail });
});

app.post("/email", function (req, res) {
  var email = req.body.email;
  if (!email) {
    res.redirect("/contact?missing=1");
  } else {
    res.send("The email you input is: " + email);
  }
});

app.post("/submitEmail", function (req, res) {
  var email = req.body.email;
  if (!email) {
    res.redirect("/contact?missing=1");
  } else {
    res.render("submitEmail", { email: email });
  }
});

/**
 * Checks if an email exists and renders the security question page.
 *
 * @param {*} req The HTTP request object containing the email to check.
 * @param {*} res The HTTP response object for sending a response.
 */
app.post("/checkEmail", async function (req, res) {
  var email = req.body.email;
  let errorMessage = "";

  // Check if email exists in database
  const result = await userCollection
    .find({ email: email })
    .project({ username: 1, securityQuestion: 1, _id: 1 })
    .toArray();
  console.log(result);
  if (result.length != 1) {
    errorMessage = "Email not found. Please try again.";
    console.log("user not found");
    res.redirect("/forgotPassword?errorMessage=" +
      encodeURIComponent(errorMessage));
    return;
  } else {
    const token = crypto.randomBytes(20).toString("hex");
    const expireTime = Date.now() + 1 * 60 * 60 * 1000;
    await userCollection.updateOne(
      { email: email },
      { $set: { resetPasswordToken: token, resetPasswordExpires: expireTime } }
    );
    console.log("token: " + token);

    // Render security question page
    res.render("securityQuestion", {
      email: email,
      securityQuestion: result[0].securityQuestion,
      token: token,
      errorMessage: errorMessage
    });
  }
});

app.get("/securityQuestion", function (req, res) {
  const errorMessage = req.query.errorMessage || "";
  const securityQuestion = req.query.securityQuestion || "";
  res.render("securityQuestion", {
    errorMessage: errorMessage, securityQuestion: securityQuestion
  });
});

app.get("/securityQuestionError", function (req, res) {
  res.render("securityQuestionError");
});

app.get("/resetPassword", function (req, res) {
  res.render("resetPassword");
});

app.get("/resetPasswordError", function (req, res) {
  res.render("resetPasswordError");
});

/**
 * Allows a user to reset their password if they answered their security
 * question correctly.
 *
 * @param req The HTTP request object containing the new password data.
 * @param res The HTTP response object for sending a response.
 */
app.post("/resetPassword", async function (req, res) {
  var newPass = req.body.newPassword;
  var confirmPass = req.body.confirmPassword;

  const result = await userCollection.find({ email: req.body.email })
    .project({
      username: 1, resetPasswordExpires: 1,
      resetPasswordToken: 1, _id: 1
    }).toArray();
  if (newPass == null || confirmPass == null) {
    res.redirect("/resetPasswordError");
    console.log("password not entered");
  } else if (result.length != 1) {
    res.redirect("/resetPasswordError");
    console.log("user not found");
  } else {
    if (newPass !== confirmPass) {
      res.redirect("/resetPasswordError");
      console.log("passwords do not match");
    } else {
      console.log("passwords match");
      var hashedPassword = await bcrypt.hash(newPass, saltRounds);
      await userCollection.updateOne({ email: req.body.email },
        { $set: { password: hashedPassword } });
      console.log("password updated");
      res.redirect("/login");
    }
  }
});

/**
 * Checks if the security question answer is correct and renders the reset
 * password page.
 *
 * @param req The HTTP request object containing the email, security answer, and token data.
 * @param res The HTTP response object for sending a response.
 */
app.post("/checkSecurityQuestion", async function (req, res) {
  var email = req.body.email;
  var securityAnswer = req.body.securityAnswer;
  var token = req.body.token;

  // finds the user with the given email
  const result = await userCollection.find({ email: email })
    .project({
      username: 1, securityAnswer: 1, resetPasswordExpires: 1,
      resetPasswordToken: 1, _id: 1
    }).toArray();
  console.log(result);

  if (securityAnswer == null) {
    res.redirect("/securityQuestionError");
  } else if (result.length != 1) {
    res.redirect("/securityQuestionError");
  } else {
    const user = result[0];
    if (await bcrypt.compare(securityAnswer, user.securityAnswer)) {
      if (Date.now() > user.resetPasswordExpires) {
        res.redirect("/tokenExpired");
      } else {
        res.render("resetPassword", { email: email, token: token });
      }
    } else {
      res.redirect("/securityQuestionError");
    }
  }
});

app.get("/logout", function (req, res) {
  req.session.destroy();
  res.redirect("/");
});

app.get("/search", sessionValidation, function (req, res) {
  res.render("search");
});

// return song results matching a given query
app.post("/searchSong", sessionValidation, async function (req, res) {
  var script = require("./scripts/likesDislikes.js");
  var list;
  var contains;
  const userLikesDislikes = await userCollection
    .find({ username: req.session.username })
    .project({ likes: 1, dislikes: 1, favourites: 1, _id: 1 }).toArray();

  //if passed filters, filter previous results
  if (req.query.artist != undefined || req.query.album != undefined) {
    list = [...req.session.searchResults];

    //filter by artist
    if (req.query.artist != undefined) {
      var artist = req.query.artist.replace(/_/g, " ");
      artist = formatSearch(artist);
      for (let i = 0; i < list.length; i++) {
        contains = false;
        var artists = formatSearch(list[i].Artist);
        artists.forEach((name) => {
          artist.forEach((term) => {
            if (name.match(new RegExp(term, "g"))) {
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
      var album = req.query.album.replace(/_/g, " ");
      album = formatSearch(album);
      for (let i = 0; i < list.length; i++) {
        var albumName = formatSearch(list[i].Album);
        contains = false;
        albumName.forEach((name) => {
          album.forEach((term) => {
            if (name.match(new RegExp(term, "g"))) {
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

    res.render("results", {
      results: list, script: script,
      userLikesDislikes: userLikesDislikes[0]
    });

    //if no filters passed, get new results
  } else {
    const userLikesDislikes = await userCollection
      .find({ username: req.session.username })
      .project({ likes: 1, dislikes: 1, favourites: 1, _id: 1 }).toArray();
    if (userLikesDislikes[0].likes == null ||
      userLikesDislikes[0].dislikes == null ||
      userLikesDislikes[0].favourites == null) {
      initLikesDislikes(userLikesDislikes[0]);
    }
    var searchTerm;
    if (req.body.song != null) {
      searchTerm = req.body.song;
    } else {
      searchTerm = req.query.q;
    }
    const result = await userCollection.find({ username: req.session.username })
      .project({ searchHistory: 1, _id: 1 }).toArray();

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
    await userCollection.updateOne({ _id: result[0]._id },
      { $set: { searchHistory: result[0].searchHistory } });
    searchTerm = formatSearch(searchTerm);
    list = await songCollection.find()
      .project({ Track: 1, Artist: 1, Album: 1, Uri: 1 }).toArray();

    //filter songs in the database based on the given name
    list.forEach((song) => {
      song.formattedName = formatSearch(song.Track);
      song.count = 0;
      song.Uri = song.Uri.split(":")[2];
    });
    
    //assign scores to songs based on how they match the terms
    var count = 0;
    list.forEach((song) => {
      song.formattedName.forEach((name) => {
        searchTerm.forEach((term) => {
          if (name.match(new RegExp(term, "g"))) {
            count += term.length / name.length;
            if (term.length === name.length) {
              count++;
            }
          }
        });
        song.count += 3 * count / song.formattedName.length;
        count = 0;
      });
    });

    //sort the songs by their scores
    list = list.sort(function (a, b) {
      return b.count - a.count;
    });
    for (let i = 0; i < list.length; i++) {
      if (list[i].count === 0) {
        list.splice(i, 1);
        i--;
      }
    }

    //truncate list for lag friendliness
    if (list.length > 25) {
      list.length = 25;
    }

    //log everything for future filtering
    req.session.searchTerm = searchTerm;
    req.session.searchResults = list;
    console.log(req.session.searchResults);
    res.render("results", {
      results: list, script: script,
      userLikesDislikes: userLikesDislikes[0]
    });
  }
});

/**
 * Attribution: https://astromacguffin.com/ref/id/62dc488124d8b5752194eccd
 * Format a given string as an array of terms
 * @param {*} searchTerm the string to format
 * @returns the formatted string
 */
function formatSearch(searchTerm) {
  return searchTerm
    .replace(/\(/gi, " ")
    .replace(/\)/gi, " ")
    .replace(/\./gi, " ")
    .replace(/!/gi, " ")
    .replace(/@/gi, " ")
    .replace(/#/gi, " ")
    .replace(/\$/gi, " ")
    .replace(/%/gi, " ")
    .replace(/\^/gi, " ")
    .replace(/&/gi, " ")
    .replace(/\*/gi, " ")
    .replace(/-/gi, " ")
    .replace(/_/gi, " ")
    .replace(/\=/gi, " ")
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

app.post("/searchHistory", async function (req, res) {
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
  var artist = req.body.artist.replace(/ /g, "_");
  var album = req.body.album.replace(/ /g, "_");
  if (artist != "" || album != "") {
    res.redirect(307, `/searchSong?artist=${artist}&album=${album}`);
  } else {
    var searchTerm = req.session.searchTerm;
    res.redirect(307, `/searchSong?q=${searchTerm}`);
  }
});

//give random songs for the user to like or dislike
app.get("/recommendationsTuning", sessionValidation, async function (req, res) {
  var script = require("./scripts/likesDislikes.js");
  var songs = [];
  var collectionSize = await songCollection.count();
  var songIds = [undefined];
  var temp;
  //get user's existing likes and dislikes
  const userLikesDislikes = await userCollection
    .find({ username: req.session.username })
    .project({ likes: 1, dislikes: 1, favourites: 1, _id: 1 }).toArray();
  if (userLikesDislikes[0].likes == null ||
    userLikesDislikes[0].dislikes == null ||
    userLikesDislikes[0].favourites == null) {
    initLikesDislikes(userLikesDislikes[0]);
  }
  for (let i = 0; i < 5; i++) {
    var counter = 0;
    //validation loop the user hasn't already rated the random song
    while (songIds.includes(temp) || userLikesDislikes[0].likes.includes(temp) ||
      userLikesDislikes[0].dislikes.includes(temp)) {
      temp = Math.floor(Math.random() * collectionSize);
      if (++counter >= 100) {
        break;
      }
    }
    if (counter >= 100) {
      break;
    }
    songIds.push(temp);
    let res = await songCollection.findOne({ _id: temp });
    res.Uri = res.Uri.split(":")[2];
    songs.push(res);
  }
  res.render("recommendationsTuning", {
    script: script,
    songs: songs, userLikesDislikes: userLikesDislikes[0]
  });
});

/**
 * Create various fields in the user's database entry
 * if they do not already exist
 * @param {*} array the user's database entry
 */
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
  await userCollection.updateOne({ _id: array._id },
    {
      $set: {
        likes: array.likes, dislikes: array.dislikes,
        favourites: array.favourites
      }
    });
}

//like a given song based on id
app.get("/like/:id", async function (req, res) {
  var userLikesDislikes = await userCollection
    .find({ username: req.session.username })
    .project({ likes: 1, dislikes: 1, _id: 1 }).toArray();
  userLikesDislikes = userLikesDislikes[0];
  var id = parseInt(req.params.id);
  if (userLikesDislikes.dislikes.includes(id)) {
    userLikesDislikes.dislikes
      .splice(userLikesDislikes.dislikes.indexOf(id), 1);
  }
  if (userLikesDislikes.likes.includes(id)) {
    userLikesDislikes.likes
      .splice(userLikesDislikes.likes.indexOf(id), 1);
  } else {
    userLikesDislikes.likes.push(id);
  }
  await userCollection.updateOne({ _id: userLikesDislikes._id },
    {
      $set: {
        likes: userLikesDislikes.likes,
        dislikes: userLikesDislikes.dislikes
      }
    });
  res.send("" + id);
});

//dislike a given song based on id
app.get("/dislike/:id", async function (req, res) {
  var userLikesDislikes = await userCollection
    .find({ username: req.session.username })
    .project({ likes: 1, dislikes: 1, _id: 1 }).toArray();
  userLikesDislikes = userLikesDislikes[0];
  var id = parseInt(req.params.id);
  if (userLikesDislikes.likes.includes(id)) {
    userLikesDislikes.likes
      .splice(userLikesDislikes.likes.indexOf(id), 1);
  }
  if (userLikesDislikes.dislikes.includes(id)) {
    userLikesDislikes.dislikes
      .splice(userLikesDislikes.dislikes.indexOf(id), 1);
  } else {
    userLikesDislikes.dislikes.push(id);
  }
  await userCollection.updateOne({ _id: userLikesDislikes._id },
    {
      $set: {
        likes: userLikesDislikes.likes,
        dislikes: userLikesDislikes.dislikes
      }
    });
  res.send("" + id);
});

//favourite a given song based on id
app.get("/favourite/:id", async function (req, res) {
  var userFavourites = await userCollection
    .find({ username: req.session.username })
    .project({ favourites: 1, _id: 1 }).toArray();
  userFavourites = userFavourites[0];
  var id = parseInt(req.params.id);
  if (userFavourites.favourites.includes(id)) {
    userFavourites.favourites
      .splice(userFavourites.favourites.indexOf(id), 1);
  } else {
    userFavourites.favourites.push(id);
  }
  await userCollection.updateOne({ _id: userFavourites._id },
    { $set: { favourites: userFavourites.favourites } });
  res.send("" + id);
});

//based on a given id, recommend the most similar song
app.post("/recommendations", async function (req, res) {
  var script = require("./scripts/likesDislikes.js");
  var id = parseInt(req.query.id);
  //send id to the ML model
  axios.get(`https://c4a7-2001-569-72ab-df00-60cb-a2c-f88e-f3b8.` +
    `ngrok-free.app/recommend/${id}`).then(async (response) => {
    // Handle the API response
    console.log(response.data);
    var recommended_song_id = parseInt(response.data.ID);
    let song = await songCollection
      .findOne({ _id: recommended_song_id });
    if (song) {
      song.Uri = song.Uri.split(":")[2];
      const userLikesDislikes = await userCollection
        .find({ username: req.session.username })
        .project({ likes: 1, dislikes: 1, favourites: 1, _id: 1 }).toArray();
      res.render("recommendations", {
        song: song,
        script: script, userLikesDislikes: userLikesDislikes[0]
      });
    } else {
      console.error("Song not found");
      res.status(404).send("Song not found");
    }
  }).catch((error) => {
    // Handle errors
    console.error(error);
    res.status(500);
    res.render("500");
  });
});

app.use(express.static(__dirname + "/public"));

app.get("*", function (req, res) {
  res.status(404);
  res.render("404");
});

app.listen(port, () => {
  console.log("Songgestions is listening on port " + port);
});
