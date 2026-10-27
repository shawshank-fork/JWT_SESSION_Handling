require("dotenv").config();

const cookieParser = require("cookie-parser");
const express = require("express");

const app = express();
const bcrypt = require("bcryptjs");

const jwt = require("jsonwebtoken");
const crypto = require("crypto");

app.use(express.json());
app.use(cookieParser());

const users = [
    {
        id: "user_1",
        email: "user1@example.com",
        passwordHash: "$2b$12$qWSAGxMzO8PBgilXut9JJOEqz6.8T/SuWDh08zuiz6ptonmthj77G"
    }
]

const sessions = new Map();
const SESSION_DURATION_MS = 15 * 60 * 1000;

app.post("/login", async (req, res) => {
    const {email, password} = req.body;

    if(!email || !password) {
        return res.status(400).json({
            error: "Email and Password are required"
        });
    }

    const user = users.find((user) => user.email === email);

    if(!user) {
        return res.status(401).json({
            error: "Invalid email or password"
        });
    }

    const passwordMatches = await bcrypt.compare(
        password,
        user.passwordHash
    );

    if(!passwordMatches) {
        return res.status(401).json({
            error: "invalid email or password"
        });
    }

    const sessionId = crypto.randomUUID();
    const expiresAt = new Date(Date.now() + SESSION_DURATION_MS);

    sessions.set(sessionId, {
        userId: user.id,
        expiresAt
    });

    const token = jwt.sign(
        {
            sub: user.id,
            email: user.email,
            sid: sessionId
        },
        process.env.JWT_SECRET,
        {
            expiresIn: "15m"
        }
    );

    const cookieOptions = {
        httpOnly: true,
        sameSite: "strict",
        secure: process.env.NODE_ENV === "production",
        maxAge: SESSION_DURATION_MS
    }

    res.cookie("token", token, cookieOptions);
    res.cookie("sessionId", sessionId, cookieOptions);

    res.status(200).json({
        message: "Login successfull",
        user: {
            id: user.id,
            email: user.email
        }
    });
});

//we always store psswordHash and never the actual pass. During login bcrypt will comapr the password supplied by the user with this hash:

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