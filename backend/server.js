const express = require("express");
const cors = require("cors");

const app = express();
app.use(cors());
app.use(express.json());

app.get("/", (req, res) => {
    res.send("Backend running");
});

app.get("/api/message", (req, res) => {
    res.json({ message: "Hello from backend" });
});

const PORT = 5001
app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});