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

const sessions = new Map(); //used to track acive login session, after succesfull login it may contain  session id(key) and {userid, expiresAt} as value
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

    const sessionId = crypto.randomUUID(); //session id is a identifier for a particular login session, application uses it to fidn the session record in the sessions map
    const expiresAt = new Date(Date.now() + SESSION_DURATION_MS);

    sessions.set(sessionId, { //sessions is a map whiich stores key value pairs, key being - session id and vlaue being userdid and email
        userId: user.id,
        expiresAt
    });

    //why save this session id or why to keep it at all? - 

    const token = jwt.sign(  //creates a signed json web token, never put passwords or other secrets in JWT payload
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

function authenticate(req, res, next) {
    const {token, sessionId} = req.cookies;

    if(!token || !sessionId) {
        return res.status(401).json({
            error: "Authenticaion cookies are missing"
        });
    }

    try {
        const decodedToken = jwt.verify(token, process.env.JWT_SECRET);

        if(decodedToken.sid !== sessionId) {
            return res.status(401).json({
                error: "JWT and session ID do not match"
            });
        }

        const session = sessions.get(sessionId);

        if(!session) {
            return res.status(401).json({
                error: "Session does not exist or was revoked"
            });
        }

        if(session.expiresAt.getTime() < Date.now()) {
            sessions.delete(sessionId);

            return res.status(401).json({
                error: "Sessions has expired"
            });
        }

        if(session.userId !== decodedToken.sub) {
            return res.status(401).json({
                error: "Session does not belong to this user"
            });
        }

        req.auth = {
            userId: decodedToken.sub,
            email: decodedToken.email,
            sessionId
        };

        next();

    } catch (error) {
        return res.status(401).json({
            error: "Invalid or expired JWT"
        });
    }
}

app.get("/me", authenticate, (req, res) => {
    res.json({
        message: "You reached a protected route",
        user: {
            id: req.auth.userId,
            email: req.auth.email
        }
    });
});

//we always store passwordHash and never the actual pass. During login bcrypt will comapr the password supplied by the user with this hash:

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