require('dotenv').config();
const express = require('express');
const session = require('express-session');
const massive = require('massive');
const authCtrl = require('./controllers/authController');
const treasureCtrl = require('./controllers/treasureController');
const auth = require('./middleware/authMiddleware');

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
app.post('/auth/login', authCtrl.login);
app.get('/auth/logout', authCtrl.logout);
app.get('/api/treasure/dragon', treasureCtrl.dragonTreasure);
app.get('/api/treasure/user', auth.usersOnly, treasureCtrl.getUserTreasure);
app.post('/api/treasure/user', auth.usersOnly, treasureCtrl.addUserTreasure)


app.listen(PORT, () => {
    console.log(`Listening to ${PORT}`);
});