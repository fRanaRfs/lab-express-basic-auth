const router = require("express").Router();
const User = require("../models/User.model");
const bcryptjs = require('bcryptjs');
const saltRounds = 10;

/// Rutas aquí ///

router.get('/signup', (req, res, next) => {
    res.render('../views/auth/signup.hbs')
})


// Add new user + redirect to profile
router.post('/signup', (req, res, next) => {
    const { username, password } = req.body;
    bcryptjs
    .genSalt(saltRounds)
    .then(salt => {
        return bcryptjs.hash(password, salt)
    })
    .then(hashedPassword => {
        return User.create({
            username,
            password: hashedPassword
        })
    })
    .then(() => {
        res.render('../views/profile.hbs')
    })
    .catch((error) => {
        next(error)
    })
});

router.get('/profile', (req, res, next) => {
    res.render('../views/profile.hbs')
    .catch((error) => {
        next(error)
    })
})

// Login
router.get('/login', (req, res, next) => {
    res.render('../views/auth/login.hbs')
    .catch((error) => {
        next(error)
    })
})

router.post('/login', (req, res, next) => {
    res.redirect('../views/profile.hbs')
    .catch((error) => {
        next(error)
    })
})





module.exports = router;