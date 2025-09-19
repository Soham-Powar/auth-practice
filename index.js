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

app.listen(3001, (err) => {
  if (err) {
    throw err;
  }
  console.log("here we go at 3001");
});
