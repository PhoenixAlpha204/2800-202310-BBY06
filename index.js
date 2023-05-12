require("./utils.js");
require("dotenv").config();
const express = require("express");
const MongoStore = require("connect-mongo");
const bcrypt = require("bcrypt");
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

var { database } = include("databaseConnection");
const userCollection = database.db(mongodb_database).collection("users");

app.set("view engine", "ejs");

app.use(express.urlencoded({ extended: false }));

var mongoStore = MongoStore.create({
    mongoUrl: `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/test`,
    crypto: {
        secret: mongodb_session_secret,
    },
});

app.use(session({
    secret: node_session_secret,
    store: mongoStore,
    saveUninitialized: false,
    resave: true,
}));

function isAuthenticated(req, res, next) {
    if (req.session.authenticated) {
        res.redirect("/loggedin");
    } else {
        next();
    }
};

function sessionValidation(req,res,next) {
    if (req.session.authenticated) {
        next();
    } else {
        res.redirect('/login');
    }
}

function adminAuthorization(req, res, next) {
    if (req.session.user_type != 'admin') {
        res.status(403);
        res.render("errorMessage", {error: "Not Authorized"});
        return;
    }
    else {
        next();
    }
}

app.get("/", isAuthenticated, (req, res) => {
    res.render("index");
});

app.get("/createUser", (req, res) => {
    res.render("createUser");
});

app.get("/login", (req, res) => {
    res.render("login");
});

app.get("/loginErrorUser", (req, res) => {
    res.render("loginErrorUser");
});

app.get("/loginErrorPassword", (req, res) => {
    res.render("loginErrorPassword");
});

app.post("/submitUser", async (req, res) => {
    var username = req.body.username;
    var password = req.body.password;

    const schema = Joi.object({
        username: Joi.string().alphanum().max(20).required(),
        password: Joi.string().max(20).required(),
    });

    const validationResult = schema.validate({ username, password });
    if (validationResult.error != null) {
        console.log(validationResult.error);
        res.redirect("/createUser");
        return;
    }

    var hashedPassword = await bcrypt.hash(password, saltRounds);

    await userCollection.insertOne({
        username: username,
        password: hashedPassword,
        user_type: "user",
    });
    console.log("Inserted user");

    req.session.authenticated = true;
    req.session.username = username;
    req.session.cookie.maxAge = expireTime;

    res.redirect("/loggedin");
});

app.post("/loggingin", async (req, res) => {
    var username = req.body.username;
    var password = req.body.password;

    const schema = Joi.string().max(20).required();
    const validationResult = schema.validate(username);
    if (validationResult.error != null) {
        console.log(validationResult.error);
        res.redirect("/login");
        return;
    }
    const result = await userCollection.find({ username: username }).project({ username: 1, password: 1, user_type: 1, _id: 1 }).toArray();

    console.log(result);
    if (result.length != 1) {
        console.log("user not found");
        res.redirect("/loginErrorUser");
        return;
    }
    if (await bcrypt.compare(password, result[0].password)) {
        console.log("correct password");
        req.session.authenticated = true;
        req.session.username = username;
        req.session.user_type = result[0].user_type;
        req.session.cookie.maxAge = expireTime;

        res.redirect("/loggedIn");
        return;
    } else {
        console.log("incorrect password");
        res.redirect("/loginErrorPassword");
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

app.get("/logout", (req, res) => {
    req.session.destroy();
    res.redirect("/");
});

app.get("/admin", sessionValidation, adminAuthorization, async (req, res) => {
    const result = await userCollection.find().project({ username: 1, _id: 1 }).toArray();
    res.render("admin", { users: result });
});

app.post("/adminUser", sessionValidation, adminAuthorization, async (req, res) => {
    const userId = req.body.userId;
    const userObjectId = new ObjectId(userId);
    await userCollection.updateOne({ _id: userObjectId }, { $set: { user_type: "admin" } });
    console.log(userId);
    res.redirect("/admin");
});

app.post("/unAdminUser", sessionValidation, adminAuthorization, async (req, res) => {
    const userId = req.body.userId;
    const userObjectId = new ObjectId(userId);
    await userCollection.updateOne({ _id: userObjectId }, { $set: { user_type: "user" } });
    console.log(userId);
    res.redirect("/admin");
});

app.get("/search", (req, res) => {
    res.render("search"); 
});

app.post("/searchSong", async (req, res) => {
    var searchTerm = formatSearch(req.body.song);
    console.log(searchTerm);
    const songCollection = database.db(mongodb_database).collection("songs_dummy");
    var list = await songCollection.find().project({ name: 1 }).toArray();
    list.forEach((song) => {
        song.formattedName = formatSearch(song.name);
        song.count = 0;
    });
    var count = 0;
    searchTerm.forEach((term) => {
        list.forEach((song) => {
            song.formattedName.forEach((name) => {
                if (term === name) {
                    count++;
                }
            });
            song.count += count;
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
    console.log(list);
    res.render("results", { results: list });
});

function formatSearch(searchTerm) {
    return searchTerm
    .replace(/\(/gi, ' ')
    .replace(/\)/gi, ' ')
    .replace(/\./gi, ' ')
    .replace(/!/gi,  ' ')
    .replace(/@/gi,  ' ')
    .replace(/#/gi,  ' ')
    .replace(/\$/gi, ' ')
    .replace(/\%/gi, ' ')
    .replace(/\^/gi, ' ')
    .replace(/&/gi,  ' ')
    .replace(/\*/gi, ' ')
    .replace(/-/gi,  ' ')
    .replace(/_/gi,  ' ')
    .replace(/=/gi,  ' ')
    .replace(/\+/gi, ' ')
    .replace(/\{/gi, ' ')
    .replace(/\[/gi, ' ')
    .replace(/\}/gi, ' ')
    .replace(/\]/gi, ' ')
    .replace(/:/gi,  ' ')
    .replace(/;/gi,  ' ')
    .replace(/"/gi,  ' ')
    .replace(/'/gi,  ' ')
    .replace(/`/gi,  ' ')
    .replace(/,/gi,  ' ')
    .replace(/>/gi,  ' ')
    .replace(/</gi,  ' ')
    .replace(/\//gi, ' ')
    .replace(/\?/gi, ' ')
    .replace(/\|/gi, ' ')
    .replace(/\\/gi, ' ')
    .replace(/\n/gi, ' ')
    .toLowerCase()
    .split(' ');
}

app.use(express.static(__dirname + "/public"));

app.get("*", (req, res) => {
    res.status(404);
    res.render("404");
});

app.listen(port, () => {
    console.log("Songgestions is listening on port " + port);
});
