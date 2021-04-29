require('dotenv').config();
const express = require('express');
const ejs = require('ejs');
const mongoose = require('mongoose');
const session = require('express-session');
const passport = require('passport');
const passportLocalMongoose = require('passport-local-mongoose');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const FacebookStrategy = require('passport-facebook').Strategy;
const findOrCreate = require('mongoose-findorcreate');


const app = express();


app.use(express.static('public'));
app.set('view engine', 'ejs');
app.use(express.urlencoded({
    extended: true
}));

app.use(session({
    secret: process.env.SECRET,
    resave: false,
    saveUninitialized: false
}));

app.use(passport.initialize());
app.use(passport.session());

mongoose.connect('mongodb+srv://admin-ilya:Test123@cluster0.yx3su.mongodb.net/userDB', {
    useNewUrlParser: true,
    useUnifiedTopology: true
});
mongoose.set('useCreateIndex', true);

const userSchema = new mongoose.Schema({
    email: String,
    password: String,
    googleId: String,
    googleEmail: String,
    googleName: String,
    facebookId: String,
    facebookName: String,
    secret: String
});

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);


const User = mongoose.model('User', userSchema);

passport.use(User.createStrategy());

passport.serializeUser(function (user, done) {
    done(null, user.id);
});

passport.deserializeUser(function (id, done) {
    User.findById(id, function (err, user) {
        done(err, user);
    });
});

// GOOGLE PASSPORT USE

passport.use(new GoogleStrategy({
        clientID: process.env.GOOGLE_CLIENT_ID,
        clientSecret: process.env.GOOGLE_CLIENT_SECRET,
        callbackURL: "http://localhost:3000/auth/google/secrets"
    },
    function (accessToken, refreshToken, profile, cb) {
        User.findOrCreate({
            googleEmail: profile.emails[0].value,
            googleId: profile.id,
            googleName: profile.displayName
        }, function (err, user) {
            return cb(err, user);
        });
    }
));

//FACEBOOK PASSPORT USE

passport.use(new FacebookStrategy({
        clientID: process.env.FACEBOOK_APP_ID,
        clientSecret: process.env.FACEBOOK_APP_SECRET,
        callbackURL: "http://localhost:3000/auth/facebook/secrets"
    },
    function (accessToken, refreshToken, profile, cb) {
        User.findOrCreate({
            facebookId: profile.id,
            facebookName: profile.displayName
        }, function (err, user) {
            return cb(err, user);
        });
    }
));

app.get('/', function (req, res) {
    res.render('home');
});

//GOOGLE GET REQUEST

app.get('/auth/google',
    passport.authenticate('google', {
        scope: ['profile', "email"]
    }));

app.get('/auth/google/secrets',
    passport.authenticate('google', {
        failureRedirect: '/login'
    }),
    function (req, res) {
        // Successful authentication wia Google go to the Secret page.
        res.redirect('/secrets');
    });

// FACEBOOK GET REQUEST

app.get('/auth/facebook',
    passport.authenticate('facebook'));

app.get('/auth/facebook/secrets',
    passport.authenticate('facebook', {
        failureRedirect: '/login'
    }),
    function (req, res) {
        // Successful authentication wia Facebook go to the Secret page.
        res.redirect('/secrets');
    });

// BODY REQUEST 

app.route('/login')

    .get(function (req, res) {
        res.render('login');
    })

    .post(function (req, res) {
        const user = new User({
            username: req.body.username,
            password: req.body.password
        });

        req.login(user, function (err) {
            if (err) {
                console.log(err);
            } else {
                res.redirect("/secrets");
            }
        })
    });

app.route('/secrets')

    .get(function (req, res) {
        User.find({
            'secret': {
                $ne: null
            }
        }, function (err, foundUser) {
            if (err) {
                console.log(err);
            } else {
                if (foundUser) {
                    res.render('secrets', {
                        usersWithSecrets: foundUser
                    });
                }
            }
        });
    });

app.route('/submit')

    .get(function (req, res) {
        if (req.isAuthenticated) {
            res.render('submit');
        } else {
            res.redirect('/login');
        }
    })

    .post(function (req, res) {
        const submittedSecret = req.body.secret;

        User.findById(req.user.id, function (err, foundUser) {
            if (err) {
                console.log(err);
            } else {
                if (foundUser) {
                    foundUser.secret = submittedSecret;
                    foundUser.save(function () {
                        res.redirect('/secrets');
                    });
                }
            }
        });
    });

app.route('/logout')

    .get(function (req, res) {
        req.logout();
        res.redirect('/');
    });

app.route('/register')

    .get(function (req, res) {
        res.render('register');
    })

    .post(function (req, res) {
        User.register({
                username: req.body.username
            }, req.body.password,
            function (err, user) {
                if (err) {
                    console.log(err);
                    res.redirect('/register');

                } else {
                    passport.authenticate('local')(req, res, function () {
                        res.redirect('/secrets');
                    });
                }
            }
        )
    });




let port = process.env.PORT;
if (port == null || port == "") {
    port = 3000;
}

app.listen(port, function () {
    console.log('Server has started.');
})