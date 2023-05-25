// Import required modules
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
const Joi = require("joi");
const ObjectId = require("mongodb").ObjectId;

// Create an instance of the Express app
const app = express();

// Set up the app configuration
const port = process.env.PORT || 3000;
const expireTime = 60 * 60 * 1000;
const mongodb_host = process.env.MONGODB_HOST;
const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;
const mongodb_database = process.env.MONGODB_DATABASE;
const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;
const node_session_secret = process.env.NODE_SESSION_SECRET;
const songgestions_email = process.env.SONGGESTIONS_SUPPORT_EMAIL;
const songgestions_password = process.env.SONGGESTIONS_SUPPORT_PASSWORD;

// Set up the database connection
var { database } = include("databaseConnection");
const userCollection = database.db(mongodb_database).collection("users");

// Define reusable functions

// Function to check if a user is authenticated
function isAuthenticated(req, res, next) {
  if (req.session.authenticated) {
    console.log("logged in");
    res.redirect("/loggedin");
  } else {
    next();
  }
}

// Function to validate session
function sessionValidation(req, res, next) {
  if (req.session.authenticated) {
    next();
  } else {
    console.log("not logged in");
    res.redirect('/login');
  }
}

// Function to authorize admin access
function adminAuthorization(req, res, next) {
  if (req.session.user_type != "admin") {
    res.status(403);
    res.render("errorMessage", { error: "Not Authorized" });
    return;
  } else {
    next();
  }
}

// Configure app settings

// Set the view engine
app.set("view engine", "ejs");

// Parse URL-encoded bodies
app.use(express.urlencoded({ extended: false }));

// Set up session store
var mongoStore = MongoStore.create({
  mongoUrl: `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/test`,
  crypto: {
    secret: mongodb_session_secret,
  },
});

// Configure session middleware
app.use(
  session({
    secret: node_session_secret,
    store: mongoStore,
    saveUninitialized: false,
    resave: true,
  })
);

// Set up common variables and middleware

// Define navigation links
const navLinks = [
  { name: "Recommendations", link: "/recommendationsTuning" },
  { name: "Browse", link: "/search" },
  { name: "Favourites", link: "/favourites" },
  { name: "Playlists", link: "/playlists" },
];

// Middleware to set common variables for views
app.use("/", (req, res, next) => {
  app.locals.navLinks = navLinks;
  app.locals.currentUrl = url.parse(req.url).pathname;
  next();
});

// Define routes

// Homepage route
app.get("/", isAuthenticated, (req, res) => {
  if (req.session.authenticated) {
    res.redirect("/loggedin");
  }
  res.render("index");
});

// Create user route
app.get("/createUser", (req, res) => {
  res.render("createUser");
});

app.post("/createUser", async (req, res) => {
  try {
    const { username, password } = req.body;
    const hashedPassword = await bcrypt.hash(password, saltRounds);
    const newUser = {
      username,
      password: hashedPassword,
    };
    await userCollection.insertOne(newUser);
    res.redirect("/login");
  } catch (error) {
    console.error(error);
    res.render("errorMessage", { error: "Failed to create user" });
  }
});

// Login route
app.get("/login", isAuthenticated, (req, res) => {
  res.render("login");
});

app.post("/login", async (req, res) => {
  try {
    const { username, password } = req.body;
    const user = await userCollection.findOne({ username });
    if (!user) {
      res.render("errorMessage", { error: "Invalid credentials" });
      return;
    }
    const passwordMatch = await bcrypt.compare(password, user.password);
    if (!passwordMatch) {
      res.render("errorMessage", { error: "Invalid credentials" });
      return;
    }
    req.session.authenticated = true;
    req.session.username = user.username;
    res.redirect("/loggedin");
  } catch (error) {
    console.error(error);
    res.render("errorMessage", { error: "Failed to log in" });
  }
});

// Logged-in route
app.get("/loggedin", sessionValidation, (req, res) => {
  res.render("loggedin");
});

// Logout route
app.get("/logout", (req, res) => {
  req.session.destroy();
  res.redirect("/");
});

app.get("/recommend", (req, res) => {
  // Make a GET request to the Flask API
  axios
    .get("http://127.0.0.1:5000/recommend/9126") // Replace with the actual API endpoint URL
    .then((response) => {
      // Handle the API response
      console.log(response.data); // Log the response data
      res.send("API response: " + JSON.stringify(response.data));
    })
    .catch((error) => {
      // Handle errors
      console.error(error);
      res.status(500).send("Error calling the API");
    });
});

// Start the server
app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
