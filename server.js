require("dotenv").config();
const express = require("express");
const sqlite3 = require("sqlite3").verbose();
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cors = require("cors");
const bodyParser = require("body-parser");

const app = express();
const PORT = process.env.PORT || 5000;

// Middleware
app.use(cors());
app.use(bodyParser.json());

// Connect to SQLite Database
const db = new sqlite3.Database("./taskTracker.db", (err) => {
    if (err) {
        console.error("Error connecting to database:", err.message);
    } else {
        console.log("Connected to SQLite database.");
        db.run(
            `CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )`
        );

        db.run(
            `CREATE TABLE IF NOT EXISTS tasks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT NOT NULL,
                description TEXT,
                status TEXT CHECK(status IN ('Pending', 'In Progress', 'Completed')) DEFAULT 'Pending',
                due_date TEXT,
                user_id INTEGER,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            )`
        );
    }
});

// Authentication Middleware
const authenticateToken = (req, res, next) => {
    const token = req.header("Authorization");
    if (!token) return res.status(401).json({ message: "Access denied. No token provided." });

    try {
        const decoded = jwt.verify(token.split(" ")[1], process.env.JWT_SECRET);
        req.user = decoded;
        next();
    } catch (err) {
        res.status(403).json({ message: "Invalid token." });
    }
};

// 🟢 User Signup
app.post("/signup", (req, res) => {
    const { name, email, password } = req.body;
    const hashedPassword = bcrypt.hashSync(password, 10);

    db.run("INSERT INTO users (name, email, password) VALUES (?, ?, ?)", [name, email, hashedPassword], function (err) {
        if (err) return res.status(400).json({ message: "Email already exists." });
        res.status(201).json({ message: "User registered successfully." });
    });
});

// 🟢 User Login
app.post("/login", (req, res) => {
    const { email, password } = req.body;

    db.get("SELECT * FROM users WHERE email = ?", [email], (err, user) => {
        if (!user || !bcrypt.compareSync(password, user.password)) {
            return res.status(401).json({ message: "Invalid email or password." });
        }

        const token = jwt.sign({ id: user.id, email: user.email }, process.env.JWT_SECRET, { expiresIn: "1h" });
        res.json({ token });
    });
});

// 🟢 Get all tasks for a user
app.get("/tasks", authenticateToken, (req, res) => {
    db.all("SELECT * FROM tasks WHERE user_id = ?", [req.user.id], (err, tasks) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(tasks);
    });
});

// 🟢 Create a task
app.post("/tasks", authenticateToken, (req, res) => {
    const { title, description, due_date } = req.body;

    db.run("INSERT INTO tasks (title, description, due_date, user_id) VALUES (?, ?, ?, ?)", [title, description, due_date, req.user.id], function (err) {
        if (err) return res.status(500).json({ error: err.message });
        res.status(201).json({ id: this.lastID, title, description, due_date, status: "Pending" });
    });
});

// 🟢 Update a task
app.put("/tasks/:id", authenticateToken, (req, res) => {
    const { title, description, status, due_date } = req.body;

    db.run("UPDATE tasks SET title = ?, description = ?, status = ?, due_date = ? WHERE id = ? AND user_id = ?", 
        [title, description, status, due_date, req.params.id, req.user.id],
        function (err) {
            if (err) return res.status(500).json({ error: err.message });
            res.json({ message: "Task updated successfully." });
        }
    );
});

// 🟢 Delete a task
app.delete("/tasks/:id", authenticateToken, (req, res) => {
    db.run("DELETE FROM tasks WHERE id = ? AND user_id = ?", [req.params.id, req.user.id], function (err) {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ message: "Task deleted successfully." });
    });
});

// Start Server
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
