require("dotenv").config();

const express = require("express");
const path = require("node:path");

const { Pool } = require("pg");
const session = require("express-session");

const passport = require("passport");
const LocalStrategy = require("passport-local").Strategy;

const bcrypt = require("bcryptjs");

// ----------- DB ------------
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
});

// ----------- APP ------------
const app = express();

// ----------- VIEW ENGINE ------------
app.set("views", path.join(__dirname, "views"));
app.set("view engine", "ejs");

// ----------- BODY PARSER ------------
app.use(express.urlencoded({ extended: false }));

// ----------- SESSION ------------
app.use(
  session({
    secret: "cats",
    resave: false,
    saveUninitialized: false,
  })
);

// ----------- PASSPORT ------------
app.use(passport.session());

// ----------- STATIC FILES ------------
const assetsPath = path.join(__dirname, "public");
app.use(express.static(assetsPath));

// ----------- PASSPORT STRATEGY ------------
passport.use(
  //localStrategy constructed with a verify callback
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

      const match = await bcrypt.compare(password, user.password);
      if (!match) {
        // passwords do not match!
        return done(null, false, { message: "Incorrect password" });
      }

      return done(null, user);
    } catch (err) {
      //error like db doesnt exist
      return done(err);
    }
  })
);

// ----------- PASSPORT SERIALIZE / DESERIALIZE ------------
passport.serializeUser((user, done) => {
  done(null, user.id);
});

passport.deserializeUser(async (id, done) => {
  // user come out of sesh - find id in db
  try {
    const { rows } = await pool.query("SELECT * FROM users WHERE id = $1", [
      id,
    ]);
    const user = rows[0];

    done(null, user);
    // it will populate req.user
  } catch (err) {
    done(err);
  }
});

// ----------- ROUTES ------------
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

app.post(
  "/log-in",
  passport.authenticate("local", {
    successRedirect: "/",
    failureRedirect: "/",
  })
);

// ----------- SERVER ------------
app.listen(3002, (err) => {
  if (err) {
    throw err;
  }
  console.log("here we go at 3001");
});
