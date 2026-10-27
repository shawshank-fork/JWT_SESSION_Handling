require("dotenv").config();

const cookieParser = require("cookie-parser");
const express = require("express");

const app = express();
const bcrypt = require("bcryptjs");

const jwt = require("jsonwebtoken");
const crypto = re

app.use(express.json());
app.use(cookieParser());

const users = [
    {
        id: "user_1",
        email: "emailOfUser1@exaple.com",
        passwordHash: "$2b$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy"
    }
]

//we always store psswordHash and never the actual pass. During login bcrypt will comapr the password supplied by the user with this hash:

const passwordMatches = await bcrypt.compare(
    suppliedPassword,
    users.passwordHash
) 

app.get("/", (req, res) => {
  res.json({
    message: "Welcome to JWT AND SESSION HANDLING "
  });
});

app.get("/health", (req, res) => {
    res.json({
        message: "Auth Server is running "
    });
});

const port = process.env.PORT || 3000;

app.listen(port, () => {
    console.log(`server running at http://localhost:${port}`);
});