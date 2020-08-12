const bcrypt = require('bcryptjs');

module.exports = {
    register: async (req, res) => {
        const {username, password, isAdmin} = req.body;
        let db = req.app.get('db');
        let result = await db.get_user([username]);
        let existingUser = result[0];
        if(existingUser){
            return res.status(409).send('Username taken')
        } 
            let salt = bcrypt.genSaltSync(10);
            let hash = bcrypt.hashSync(password, salt);
            let registeredUser = await db.register_user([isAdmin, username, hash])
            let user = registeredUser[0]
            req.session.user = {
                isAdmin: user.is_admin,
                id: user.id,
                username: user.username
            }
            return res.status(201).send(req.session.user)
        
    },

    login: async (req, res) => {
        const {username, password} = req.body
        let db = req.app.get('db');
        let result = await db.get_user([username]);
        let foundUser = result[0]
        if(!foundUser){
            return res.status(401).send('User not found. Please register as a new user before logging in.')
        }
        let isAuthenticated = bcrypt.compareSync(password, user.hash)
        if (!isAuthenticated){
            res.status(403).send('Incorrect password')
        }
        req.session.user = {
            username: foundUser[0].username,
            password: foundUser[0].password
        }
        res.status(200).send(req.session.user)
    }
}