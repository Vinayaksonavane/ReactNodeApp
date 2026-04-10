const express = require("express");
const cors = require("cors");
const sql = require("mssql");
const jwt = require("jsonwebtoken");
require("dotenv").config();

const app = express();
app.use(cors());
app.use(express.json());

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
    .catch(err => console.log(err));

// LOGIN API
app.post("/api/login", async (req, res) => {
    const { username, password } = req.body;

    console.log("Login request:", username);

    try {
        const result = await sql.query`
            SELECT * FROM K_USER_DTL 
            WHERE LOWER(UsrCd) = LOWER(${username})
        `;

        if (result.recordset.length === 0) {
            return res.status(401).json({ message: "User not found" });
        }

        const user = result.recordset[0];

        console.log("Input username:", username);
        console.log("DB user object keys:", Object.keys(user));
        console.log("DB UsrPwd value:", user.UsrPwd);

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
        console.log(err);
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