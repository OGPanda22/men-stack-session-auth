const express = require("express");
const router = express.Router();
const User = require("../models/user.js");
const bcrypt = require("bcrypt");



router.get("/sign-up", (req, res) => {
    res.render("auth/sign-up.ejs");
  });
  
router.post("/sign-up", async (req, res) => {

    //check to see if user exists
    const userInDatabase = await User.findOne({ username: req.body.username });

    //if yes, reject it
    if (userInDatabase) {
        return res.status(401).send("Username already taken.");
      }

    if (req.body.password !== req.body.confirmPassword) {
        return res.status(401).send("Password and Confirm Password must match");
      }

    //hash the password
    const hashedPassword = bcrypt.hashSync(req.body.password, 10);
    req.body.password = hashedPassword;

    const user = await User.create(req.body);

    res.send("Form submission accepted!");
  });
  
router.get("/sign-in", (req, res) => {
    res.render("auth/sign-in.ejs");
  });
  
router.post("/sign-in", async (req, res) => {
    //does the user exist
    const userInDatabase = await User.findOne({ username: req.body.username });

    //if no, throw error
    if (!userInDatabase) {
        return res.status(401).send("Login failed. Please try again.");
      };
    //does the password hash match?
    const validPassword = bcrypt.compareSync(
        req.body.password,
        userInDatabase.password
      );

    //if no, throw error
    if (!validPassword) {
        return res.status(401).send("Login failed. Please try again.");
      };

    //allow login, start session
    req.session.user = {
        username: userInDatabase.username,
        _id: userInDatabase._id
      };
 
      res.redirect("/");

  });
  
router.get("/sign-out", (req, res) => {
    req.session.destroy();
    res.redirect("/");
  });

module.exports = router;
