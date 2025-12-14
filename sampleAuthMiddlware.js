function isAuth(req, res, next) {
  if (req.isAuthenticated()) {
    next();
  } else {
    res.redirect("/log-in");
    //or
    // res.status(401).send('You are not authorized to view this page');
  }
}
//just pass above middleware to any route to protect it

// example

// router.get('/protected-route', isAuth, (req, res) => {
//   res.send('This is a protected route and u reached');
// });

//for below..there must be admin(boolean) or role property in db user table
function isAdmin(req, res, next) {
  if (req.user && req.user.role === "admin") {
    next();
  } else {
    res.redirect("/");
    //or
    // res.status(403).send('You do not have permission to view this page as u no admin');
  }
}

//here we can use isAuth, isAdmin in line
