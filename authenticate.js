const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const User = require('./models/user');
const JwtStrategy = require('passport-jwt').Strategy;
const ExtractJwt = require('passport-jwt').ExtractJwt;
const jwt = require('jsonwebtoken');
const config = require('./config');

passport.use(new LocalStrategy(User.authenticate()));
passport.serializeUser(User.serializeUser());
passport.deserializeUser(User.deserializeUser());

exports.getToken = function(user) {
    return jwt.sign(user, config.secretKey,
        {expiresIn: 3600});
}

let opts = {};
opts.jwtFromRequest = ExtractJwt.fromAuthHeaderAsBearerToken();
opts.secretOrKey = config.secretKey;

exports.jwtPassport = passport.use(new JwtStrategy(opts, (jwt_payload, done) => {
    console.log("JWT payload: ", jwt_payload);
    User.findOne({id: jwt_payload.sub}, (err, user) => {
        if (err) {
            return done(err, false);
        } else if (user) {
            return done(null, user);
        } else {
            return done(null, false);
        }
    });
}));

exports.verifyAdmin = (req, res, next) => {
    console.log("User: " + req.user);
    const authHeader = req.headers.authorization;

    if (authHeader) {
        const token = authHeader.split(' ')[1];
        jwt.verify(token, config.secretKey, (err, test) => {
            // console.log(test._id)
            if (err) {
                next(err);
            } else {
                User.findOne({_id: test._id}, (err, user) => {
                    if (user.admin === true) {
                        return next()
                    }
                    else {
                        res.statusCode = 403
                        err = new Error("You are not authorized to perform this operation")
                        return next(err)
                    }
                });
            }
        });
    }
    /*if (req.user.admin === true) {
        next();
    } else {
        let err = new Error('You are not authorized to perform this operation');
        err.status = 403;
        return next(err);
    }*/
}

exports.verifyUser = passport.authenticate('jwt', {session: false});
