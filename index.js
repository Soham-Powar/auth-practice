const express = require("express");
const path = require("node:path");
const app = express();

require("dotenv").config();

const { Pool } = require("pg");
const session = require("express-session");
const passport = require("passport");
const LocalStrategy = require("passport-local").Strategy;

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
});

app.set("views", path.join(__dirname, "views"));
app.set("view engine", "ejs");

//new stuff
app.use(session({ secret: "cats", resave: false, saveUninitialized: false }));
app.use(passport.session());
app.use(express.urlencoded({ extended: false }));

const assetsPath = path.join(__dirname, "public");
app.use(express.static(assetsPath));

app.get("/", (req, res) => res.render("index"));
app.get("/sign-up", (req, res) => res.render("sign-up-form"));

//post req sign up
app.post("/sign-up", async (req, res, next) => {
  try {
    await pool.query("INSERT INTO users (username, password) VALUES ($1, $2)", [
      req.body.username,
      req.body.password,
    ]);
    res.redirect("/");
  } catch (err) {
    return next(err);
  }
});

//or u can strat = new Local...and the passport.use(strategy)
// HTTP is a stateless protocol, meaning that each
// request to an application can be understood in
// isolation - without any context from previous
// requests. This poses a challenge for web
// applications with logged in users, as the
// authenticated user needs to be remembered
// across subsequent requests as they navigate the
// application.

// To solve this challenge, web applications make
// use of sessions, which allow state to be
// maintained between the application server and
// the user's browser. A session is established by
// setting an HTTP cookie in the browser, which
// the browser then transmits to the server on
// every request. The server uses the value of the
// cookie to retrieve information it needs across
// multiple requests. In effect, this creates a
// stateful protocol on top of HTTP.

// cookies enable servers to store stateful
// information on user device(cart)
passport.use(
  new LocalStrategy(async (username, password, done) => {
    try {
      const { rows } = await pool.query(
        "select * from users where username = $1",
        [username]
      );
      const user = rows[0];

      //false means user not found
      if (!user) {
        return done(null, false, { message: "Incorrect username" });
      }

      if (user.password !== password) {
        return done(null, false, { message: "Incorrect password" });
      }
      //user found
      return done(null, user);
    } catch (err) {
      //error like db doesnt exist
      return done(err);
    }
  })
);

// To make sure our user is logged in, and to
// allow them to stay logged in as they move
// around our app, passport internally calls a
// function from express-session that uses some
// data to create a cookie called connect.sid
// which is stored in the user’s browser. These
// next two functions define what bit of
// information passport is looking for when it
// creates and then decodes the cookie.

// it takes a callback which contains info
// we wish to store in session data

// WHEN SESSION CREATED - THIS WILL RECEIVE
// USER OBJ FOUND ON SUCC REQ AND STORE ITS ID
// PROPERTY IN SESSION DATA
passport.serializeUser((user, done) => {
  done(null, user.id);
});

// it is called when retrieving a session, where it
// will extract data we serialized in it and then
// ultimately attach something to .user property
// of req obj for use in rest of req
// req.user

// FOR SOME OTHER REQ, IF IT FINDS MATCHING SESSION
// FOR THAT REQ, BELOW WILL RETRIEVE ID STORED
// IN SESSION DATA AND USE TO QUERY DB

// THEN THE DONE(NULL, USER) ATTACHES THE USER
// OBJECT TO THE REQ.USER
// SO WE CAN ACCESS REQ.USER IN REST OF REQ

// we just define them...passport calls them in bg
passport.deserializeUser(async (id, done) => {
  try {
    const { rows } = await pool.query("SELECT * FROM users WHERE id = $1", [
      id,
    ]);
    const user = rows[0];

    done(null, user);
  } catch (err) {
    done(err);
  }
});

app.listen(3001, (err) => {
  if (err) {
    throw err;
  }
  console.log("here we go at 3001");
});
