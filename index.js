const express = require('express')
const logger = require('morgan')
const passport = require('passport')

const LocalStrategy = require('passport-local').Strategy
const JwtStrategy = require('passport-jwt').Strategy

const jwt = require('jsonwebtoken')
const cookieParser = require('cookie-parser');

const bcrypt = require('bcrypt');
const saltRounds = 8;

const fortune = require('fortune-teller')

const port = 3000
const app = express()

const users = require('./users.json')

app.use(logger('dev'))
app.use(cookieParser());

const jwtSecret = require('crypto').randomBytes(16) // 16*8= 256 random bits 

var cookieExtractor = function (req) {
  var token = null;
  if (req && req.cookies) {
    token = req.cookies.token_cookie;
  }
  return token;
};

passport.use('jwt', new JwtStrategy({
  jwtFromRequest: cookieExtractor,
  secretOrKey: jwtSecret
},  
  function (jwt_payload, done) {
    // Find if the username stored in the JWT is in the database.
    for (let i = 0; i < users.length; i++) {
      const currentUserIteration = users[i]['username'];
      // If there is a match, we authenticate.
      if (currentUserIteration === jwt_payload.sub){
        user = {username:currentUserIteration}
        return done(null, user);
      }
    }
    return done(null, false);
  }
));

passport.use('local', new LocalStrategy(
  {
    usernameField: 'username',
    passwordField: 'password',
    session: false // we are storing a JWT in the cookie with all the required session data. The server is session-less
  },
  function (username, password, done) {
    // Find if the introduced username is in the database.
    for (let i = 0; i < users.length; i++) {
      const currentUserIteration = users[i]['username'];
      // If there is a match, check if the introduced
      // password corresponds to the hash stored in the database.
      if (currentUserIteration === username){
        user = {username:currentUserIteration}
        hashedPassword = users[i]['hash']
        if (bcrypt.compareSync(password, hashedPassword)) {
          return done(null, user)
        }
        // Otherwise, the introduced password is wrong.
        return done(null, false)
      }
    }
    return done(null, false)
  }
))

app.use(express.urlencoded({ extended: true })) // needed to retrieve html form fields
app.use(passport.initialize()) // we load the passport auth middleware to our express application. It should be loaded before any route.

app.get('/',
  passport.authenticate('jwt', { failureRedirect: '/login', session: false }),
  (req, res) => {
    res.send(fortune.fortune())
  }
)

app.get('/login',
  (req, res) => {
    res.sendFile('login.html', { root: __dirname })
  }
)

app.post('/login',
  passport.authenticate('local', { failureRedirect: '/login', session: false }),
  (req, res, next) => { //
    // we should create here the JWT for the fortune teller and send it to the user agent inside a cookie.
    // This is what ends up in our JWT
    const currentDate = Math.floor(Date.now() / 1000)
    const jwtClaims = {
      sub: req.user.username,
      iss: 'localhost:3000',
      aud: 'localhost:3000',
      exp: currentDate + 604800, // 1 week (7×24×60×60=604800s) from now (expiration time)
      role: 'user' // just to show a private JWT field
    }

    // generate a signed json web token. By default the signing algorithm is HS256 (HMAC-SHA256), i.e. we will 'sign' with a symmetric secret
    const token = jwt.sign(jwtClaims, jwtSecret)

    res.cookie('token_cookie', token, {expire : currentDate + 604800})
    res.redirect('/')
    // console.log(`Token sent. Debug at https://jwt.io/?value=${token}`)
    // console.log(`Token secret (for verifying the signature): ${jwtSecret.toString('base64')}`)
  }
)

app.get('/logout',
  (req,res) => {
    res.clearCookie('token_cookie')
    res.send('You have successfully logged out!')
  }
  )

app.use(function (err, req, res, next) {
  console.error(err.stack)
  res.status(500).send('Something broke!')
})

app.listen(port, () => {
  console.log(`Example app listening at http://localhost:${port}`)
})