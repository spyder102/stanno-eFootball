const express = require("express");
const session = require("express-session");
const bcrypt = require("bcryptjs");
const fs = require("fs");

const app = express();

const PORT = process.env.PORT || 3000;
const USERS_FILE = "./users.json";


// =============== SETTINGS ===============

app.use(express.urlencoded({ extended: true }));

app.set("trust proxy", 1);

// Login sessions
app.use(session({
    secret: process.env.SESSION_SECRET || "development-only-secret",
    resave: false,
    saveUninitialized: false,
    cookie: {
        httpOnly: true,
        secure: process.env.NODE_ENV === "production",
        sameSite: "lax",
        maxAge: 1000 * 60 * 60 * 24
    }
}));

// Block access to private user data
app.get("/users.json", (req, res) => {
    res.status(404).send("Not found");
});

// Serve website files
app.use(express.static(__dirname, {
    dotfiles: "deny",
    index: "index.html"
}));


// ================= USER DATABASE =================

function getUsers() {

    if (!fs.existsSync(USERS_FILE)) {
        fs.writeFileSync(USERS_FILE, "[]");
    }

    return JSON.parse(
        fs.readFileSync(USERS_FILE, "utf8")
    );
}


function saveUsers(users) {

    fs.writeFileSync(
        USERS_FILE,
        JSON.stringify(users, null, 2)
    );

}
function requireAdmin(req, res, next) {

    if (
        !req.session.user ||
        req.session.user.role !== "admin"
    ) {
        return res.status(403).send(`
            <h1>Access Denied</h1>
            <p>Administrator access is required.</p>
            <a href="/login.html">Back to Login</a>
        `);
    }

    next();
}


// ================= PROTECTED PAGE =================

app.get("/dashboard", (req, res) => {

    if (!req.session.user) {

        return res.redirect("/login.html");

    }

    res.sendFile(__dirname + "/dashboard.html");

});
// ================= REGISTRATION =================

app.post("/register", async (req, res) => {

    const { username, password } = req.body;

    // Basic validation
    if (!username || !password) {
        return res.send(`
            <h1>Registration Failed</h1>
            <p>Please provide a username and password.</p>
            <a href="/register.html">Try again</a>
        `);
    }

    if (username.length < 3) {
        return res.send(`
            <h1>Registration Failed</h1>
            <p>Username must contain at least 3 characters.</p>
            <a href="/register.html">Try again</a>
        `);
    }

    if (password.length < 8) {
        return res.send(`
            <h1>Registration Failed</h1>
            <p>Password must contain at least 8 characters.</p>
            <a href="/register.html">Try again</a>
        `);
    }

    const users = getUsers();

    // Check whether username already exists
    const existingUser = users.find(
        user => user.username.toLowerCase() === username.toLowerCase()
    );

    if (existingUser) {
        return res.send(`
            <h1>Registration Failed</h1>
            <p>That username is already registered.</p>
            <a href="/register.html">Try again</a>
        `);
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 12);

    // New users are NOT authorized initially
    const newUser = {
        username: username,
        password: hashedPassword,
        authorized: false,
        role: "member"
    };

    users.push(newUser);

    saveUsers(users);

    res.send(`
        <h1>Registration Successful! 🎉</h1>
        <p>Your account has been created.</p>
        <p>Your account is waiting for administrator approval.</p>
        <a href="/login.html">Go to Login</a>
    `);

});



// ================= LOGIN =================

app.post("/login", async (req, res) => {

    const { username, password } = req.body;

    const users = getUsers();

    const user = users.find(
        u => u.username === username
    );


    if (!user) {

        return res.send(`
            <h1>Login failed</h1>
            <p>Invalid username or password.</p>
            <a href="/login.html">Try again</a>
        `);

    }


    const passwordCorrect =
        await bcrypt.compare(password, user.password);


    if (!passwordCorrect) {

        return res.send(`
            <h1>Login failed</h1>
            <p>Invalid username or password.</p>
            <a href="/login.html">Try again</a>
        `);

    }


    // Check authorization
    if (user.authorized !== true) {

        return res.send(`
            <h1>Access Pending</h1>
            <p>Your account has not been authorized yet.</p>
            <a href="/login.html">Back to login</a>
        `);

    }


    req.session.user = {
        username: user.username,
        role: user.role
    };


    res.redirect("/dashboard");

});


// ================= LOGOUT =================

app.get("/logout", (req, res) => {

    req.session.destroy(() => {

        res.redirect("/");

    });

});
// ================= ADMIN =================

// Get users
app.get("/admin/users", requireAdmin, (req, res) => {

    const users = getUsers();

    const safeUsers = users.map(user => ({
        username: user.username,
        authorized: user.authorized,
        role: user.role
    }));

    res.json(safeUsers);

});


// Authorize a user
app.post("/admin/authorize", requireAdmin, (req, res) => {

    const { username } = req.body;

    const users = getUsers();

    const user = users.find(
        u => u.username === username
    );

    if (!user) {
        return res.status(404).send("User not found.");
    }

    user.authorized = true;

    saveUsers(users);

    res.redirect("/admin.html");

});


// Disable a user
app.post("/admin/disable", requireAdmin, (req, res) => {

    const { username } = req.body;

    const users = getUsers();

    const user = users.find(
        u => u.username === username
    );

    if (!user) {
        return res.status(404).send("User not found.");
    }

    user.authorized = false;

    saveUsers(users);

    res.redirect("/admin.html");

});


// ================= START SERVER =================

app.listen(PORT, "0.0.0.0", () => {
    console.log("================================");
    console.log(" STANNO eFOOTBALL SERVER ONLINE");
    console.log("================================");
    console.log(`Server running on port ${PORT}`);
});