const express = require('express');
const passport = require('passport');
const BasicStrategy = require('passport-http').BasicStrategy;
const jwt = require('jsonwebtoken');

const app = express();
const port = 3000;

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Sample one-liner posts
const oneLiners = [
    "A stitch in time saves nine.",
    "Fortune favors the bold.",
    "Actions speak louder than words.",
    "What goes around comes around.",
    "No pain, no gain."
];

// Blacklisted tokens - tokens added on logout
const blacklistedTokens = new Set();

// FOR DEMO ONLY, DO NOT DO THIS IN PRODUCTION
const MYSECRETJWTKEY = "mysecret";

// Simulated user database (In real applications, use a database)
const users = {
    adminUser: { username: "adminUser", password: "pass", role: "admin" },
    normalUser: { username: "normalUser", password: "pass", role: "user" }
};

// Passport Basic Authentication Strategy
passport.use(new BasicStrategy(function (username, password, done) {

    const user = users[username];

    if (user && user.password === password) {
        return done(null, { username: user.username, role: user.role }); // Assigning user a role 
    } else {
        return done(null, false);
    }
}));

// Sign in route to generate JWT token
app.post('/signin', passport.authenticate('basic', { session: false }), (req, res) => {
    const refreshToken = jwt.sign({ username: req.user.username, role: req.user.role }, MYSECRETJWTKEY, { expiresIn: '1h' });
    const accessToken = jwt.sign({ username: req.user.username, role: req.user.role }, MYSECRETJWTKEY, { expiresIn: '1m' });
    res.json({ 
        refreshToken: refreshToken, 
        accessToken: accessToken
    });
});

app.post('/refresh', (req, res) => {
    const { refreshToken } = req.body;
    if (!refreshToken) {
        return res.status(400).json({ message: 'Invalid input' });
    }

    if (blacklistedTokens.has(refreshToken)) {
        return res.status(403).json({ message: 'Forbidden' });
    }

    jwt.verify(refreshToken, MYSECRETJWTKEY, (err, user) => {
        if (err) {
            return res.status(403).json({ message: 'Forbidden' });
        }
        const accessToken = jwt.sign({ username: user.username, role: user.role }, MYSECRETJWTKEY, { expiresIn: '1m' });
        res.json({ 
            accessToken: accessToken
        });
    });

});

app.post('/logout', (req, res) => {
    const refreshToken  = req.body.refreshToken;
    const accessToken = req.body.accessToken;
    if (!refreshToken || !accessToken) {
        return res.status(400).json({ message: 'Invalid input' });
    }

    if (blacklistedTokens.has(refreshToken) || blacklistedTokens.has(accessToken)) {
        return res.status(403).json({ message: 'Forbidden' });
    }

    blacklistedTokens.add(refreshToken);
    blacklistedTokens.add(accessToken);

    jwt.verify(refreshToken, MYSECRETJWTKEY, (err, user) => {
        if (err) {
            return res.status(403).json({ message: 'Forbidden' });
        }
        res.json({ 
            message: 'Logged out successfully'
        });
    });

});

// Middleware to validate JWT
const authenticateJWT = (req, res, next) => {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ message: 'Unauthorized' });
    }

    const token = authHeader.split(' ')[1];

    if (blacklistedTokens.has(token)) {
        return res.status(403).json({ message: 'Forbidden' });
    }

    jwt.verify(token, MYSECRETJWTKEY, (err, user) => {
        if (err) {
            return res.status(403).json({ message: 'Forbidden' });
        }
        req.user = user;
        next();
    });
};

// Middleware to check role-based access
const authorizeRole = (role) => {
    return (req, res, next) => {
        if (req.user.role !== role) {
            return res.status(403).json({ message: 'Forbidden: Insufficient permissions' });
        }
        next();
    };
};

// Route available for both "user" and "admin"
app.get('/posts', authenticateJWT, (req, res) => {
    res.json(oneLiners);
});

// Route available only for "admin"
app.post('/posts', authenticateJWT, authorizeRole('admin'), (req, res) => {
    const { message } = req.body;
    if (!message || typeof message !== 'string') {
        return res.status(400).json({ message: 'Invalid input' });
    }

    oneLiners.push(message);
    res.status(201).json({ message: 'Post added successfully', posts: oneLiners });
});

app.listen(port, () => {
    console.log(`Example app listening on port ${port}`);
});
