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
const bcrypt = require("bcryptjs");
app.use(
  session({
    // process.env.secret
    // to validate session
    secret: "cats",
    resave: false,
    saveUninitialized: false,
    // above 2 - how session reacts when there
    // is no changes in browser

    // session id stored in cookie
    // so
    // cookie: { maxAge: ...}

    // if using session store
    // store: sessionStore
    // and before
    // const sessionStore = new MongoStore?
  })
);
app.use(passport.session());

app.use(express.urlencoded({ extended: false }));

const assetsPath = path.join(__dirname, "public");
app.use(express.static(assetsPath));

app.get("/", (req, res) => res.render("index", { user: req.user }));

app.get("/log-out", (req, res, next) => {
  req.logout((err) => {
    if (err) {
      return next(err);
    }
    res.redirect("/");
  });
});

app.get("/sign-up", (req, res) => res.render("sign-up-form"));

//post req sign up
app.post("/sign-up", async (req, res, next) => {
  try {
    const hashedPassword = await bcrypt.hash(req.body.password, 10);
    await pool.query("INSERT INTO users (username, password) VALUES ($1, $2)", [
      req.body.username,
      hashedPassword,
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
        // null means no theres not any error
        // false means but user also not there(dont validate)
        return done(null, false, { message: "Incorrect username" });
      }

      const match = await bcrypt.compare(password, user.password);
      if (!match) {
        // passwords do not match!
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
  // put user in sesh - put userid in sesh
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
  // user come out of sesh - find id in db
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

// magic

app.post(
  "/log-in",
  passport.authenticate("local", {
    successRedirect: "/",
    failureRedirect: "/",
  })
);

app.listen(3002, (err) => {
  if (err) {
    throw err;
  }
  console.log("here we go at 3001");
});

// Authentication
// Who the user is?

// Authorization - OAuth
// Who has access to what resources
// What can he do? only get...get/post etc

// cookie
// for some request(first) server sends a cookie
// to client through set-cookie resp header (if authenticated)
// for all the following requests(in domain context) - the browser
// sends that cookie through 'cookie' req header to server (so no re-login)
// hence the server knows
// how long? expires= piece of set cookie

// cookie vs session

// cookie has data stored in browser
// browser will attach that cookie key-value pair
// to every http request it does

// session gets stored on server side (express js appln)
// session stores bigger data as in cookie u cant
// put much data (becomes tedious)
// also..cookie we cant store user credentials
// as hacker can easily get access
// session is used to store info about a particular
// user moving through client

// session store implementation
// what persistent memory we will store our seshs in
// so in prod env we can store the info we get abt user
// in a db
// by default, express session middleware comes with
// a implementation of session store that uses a
// appln memory (not scalable)

// setup a sesh store ~ connect db to exp-sesh middleware
// sesh store == connect-pg-simple
