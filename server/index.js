require('dotenv').config();
const express = require('express');
const session = require('express-session');
const massive = require('massive');
const authCtrl = require('./controllers/authController');

const app = express();
const PORT = 4000;

app.use(express.json());

const {CONNECTION_STRING, SESSION_SECRET} = process.env;

massive({
    connectionString: CONNECTION_STRING,
    ssl: { rejectUnauthorized: false}

}).then(db => {
    app.set('db', db);
    console.log('db connected')
});

app.use(
    session({
        secret: SESSION_SECRET,
        saveUninitialized: false,
        resave: true
    })
)

app.post('/auth/register', authCtrl.register);
app.post('/auth/login', authCtrl.login)

app.listen(PORT, () => {
    console.log(`Listening to ${PORT}`);
});