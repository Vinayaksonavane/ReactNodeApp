const express = require("express");
const cors = require("cors");
const sql = require("mssql");
const jwt = require("jsonwebtoken");
const rateLimit = require("express-rate-limit");
require("dotenv").config();

// Validate required env vars at startup
const requiredEnvVars = ["JWT_SECRET", "DB_USER", "DB_PASSWORD", "DB_SERVER", "DB_NAME"];
requiredEnvVars.forEach(key => {
    if (!process.env[key]) {
        console.error(`FATAL: Missing required environment variable: ${key}`);
        process.exit(1);
    }
});

const app = express();

// Bug #11: Restrict CORS to specific allowed origins
const allowedOrigins = process.env.ALLOWED_ORIGINS
    ? process.env.ALLOWED_ORIGINS.split(",")
    : ["http://localhost:3000"];

app.use(cors({
    origin: allowedOrigins,
    credentials: true,
    optionsSuccessStatus: 200
}));

app.use(express.json());

// Bug #9: Rate limit login endpoint — max 5 attempts per 15 minutes per IP
const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 5,
    message: { message: "Too many login attempts. Please try again after 15 minutes." }
});

// DB CONFIG
const dbConfig = {
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    server: process.env.DB_SERVER,
    database: process.env.DB_NAME,
    options: {
        encrypt: false,
        trustServerCertificate: true
    }
};

// CONNECT DB
sql.connect(dbConfig)
    .then(() => console.log("Connected to SQL Server"))
    .catch(err => {
        console.error("Database connection failed:", err);
        process.exit(1);
    });

// LOGIN API
app.post("/api/login", loginLimiter, async (req, res) => {
    const { username, password } = req.body;

    try {
        const result = await sql.query`
            SELECT * FROM K_USER_DTL
            WHERE LOWER(UsrCd) = LOWER(${username})
        `;

        if (result.recordset.length === 0) {
            return res.status(401).json({ message: "User not found" });
        }

        const user = result.recordset[0];

        if (!user.UsrPwd) {
            return res.status(500).json({ message: "Password missing in DB" });
        }

        const isMatch = password.trim() === user.UsrPwd.trim();

        if (!isMatch) {
            return res.status(401).json({ message: "Invalid password" });
        }

        const token = jwt.sign(
            { id: user.UsrSrlNo, username: user.UsrCd },
            process.env.JWT_SECRET,
            { expiresIn: "1h" }
        );

        res.json({ token });

    } catch (err) {
        console.error(err);
        res.status(500).json({ error: err.message });
    }
});

// PROTECTED API
app.get("/api/data", verifyToken, (req, res) => {
    res.json({ message: "Secure data access granted" });
});

// TOKEN VERIFY
function verifyToken(req, res, next) {
    const bearer = req.headers["authorization"];
    if (!bearer) return res.sendStatus(403);

    const token = bearer.split(" ")[1];

    jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
        if (err) return res.sendStatus(403);
        req.user = decoded;
        next();
    });
}

const PORT = 5000;
app.listen(PORT, () => console.log(`Server running on ${PORT}`));