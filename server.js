// server.js
require('dotenv').config()

const express = require('express');
const cors = require('cors');
const con = require('./db');
var mysql = require('mysql');
const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken');

const app = express();
app.use(cors());
app.use(express.json());

app.post('/login', (req, res) => {
    const { username, password } = req.body.params;
    // console.log(username, password);
    // console.log(req.body.params);

    if (!username || !password) {
        return res.status(400).json({ error: 'Username and password are required.' });
    }

    // Query the database to retrieve user data
    con.query('SELECT * FROM login WHERE username = ?', [username], (error, results) => {
        if (error) {
            console.error('Error executing SQL query:', error);
            return res.status(500).json({ error: 'Internal Server Error' });
        }

        // Check if user with the provided username exists
        if (results.length === 0) {
            return res.status(401).json({ access: false, error: 'Invalid username or password.' });
        }

        const user = results[0];

        // Compare the provided password with the hashed password stored in the database
        bcrypt.compare(password, user.password, (err, result) => {
            if (err) {
                console.error('Error comparing passwords:', err);
                return res.status(500).json({ error: 'Internal Server Error' });
            }

            if (result) {
                const accessToken = jwt.sign({ username: user.username }, process.env.ACCESS_TOKEN_SECRET, { expiresIn: '1h' });
                return res.json({ accessToken: accessToken });
            } else {
                return res.status(401).json({ error: 'Invalid username or password.' });
            }
        });
    });
});

app.get('/post',authJsonwebToken, (req, res) => {
    const { username, password } = req.query;
    // console.log(username, password);
    // console.log(req);
  
    if (!username || !password) {
      return res.status(400).json({ error: "username and password are required." });
    }
  
    con.query("SELECT * FROM login WHERE username = ?", [username], (error, results, fields) => {
        if (error) {
            console.error('Error executing SQL query:', error);
            return res.status(500).json({ error: 'Internal Server Error' });
        }

        if (results.length > 0) {
            return res.status(409).json({ error: "Username already used." });
        }

        bcrypt.hash(password, 10, (err, hashedPassword) => {
            if (err) {
                return res.status(500).json({ error: err.message });
            }

            con.query(
                "INSERT INTO login (password, username) VALUES (?, ?)",
                [hashedPassword, username],
                (err, results) => {
                    if (err) {
                        return res.status(500).json({ error: err.message });
                    }
                    res.status(201).json({ message: "User registered successfully." });
                }
            );
        });
    });
});
app.post('/gettoken', async (req, res) => {
    const password = req.body.password
    const passwordtk = {name : password}

    const accessToken = jwt.sign(passwordtk, process.env.ACCESS_TOKEN_SECRET)
    res.json({accessToken: accessToken})
});

function authJsonwebToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if(token == null) return res.sendStatus(401);

    jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, user) => {
        if (err) return res.sendStatus(403);
        req.username = user;
        next();
    })
}

app.listen(3001, () => console.log('Example app is listening on port 3001.'));
