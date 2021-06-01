const express = require('express')
const logger = require('morgan')
const passport = require('passport')


const LocalStrategy = require('passport-local').Strategy
var JwtStrategy = require('passport-jwt').Strategy
const OAuth2Strategy = require('passport-oauth2').Strategy

const jwt = require('jsonwebtoken')
const cookieParser = require('cookie-parser');

const bcrypt = require('bcrypt');
const saltRounds = 8;

const fortune = require('fortune-teller')

const port = 3000
const jwtSecret = require('crypto').randomBytes(16) // 16*8= 256 random bits 
const app = express()

const users = require('./users.json')

app.use(logger('dev'))
app.use(cookieParser());

// bcrypt.hash('superexam', saltRounds, 
//   (err, hash) => {
//     console.log(hash)
//   })

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
    for (let i = 0; i < users.length; i++) {
      const currentUserIteration = users[i]['username'];
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
    for (let i = 0; i < users.length; i++) {
      const currentUserIteration = users[i]['username'];
      if (currentUserIteration === username){
        user = {username:currentUserIteration}
        hashedPassword = users[i]['hash']
        if (bcrypt.compareSync(password, hashedPassword)) {
          return done(null, user)
        }
        return done(null, false)
      }
    }
    return done(null, false)
  }
))

passport.use(new OAuth2Strategy({
  authorizationURL: 'https://www.example.com/oauth2/authorize',
  tokenURL: 'https://www.example.com/oauth2/token',
  clientID: EXAMPLE_CLIENT_ID,
  clientSecret: EXAMPLE_CLIENT_SECRET,
  callbackURL: "http://localhost:3000/auth/example/callback"
},
function(accessToken, refreshToken, profile, cb) {
  User.findOrCreate({ exampleId: profile.id }, function (err, user) {
    return cb(err, user);
  });
}
));














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
      role: 'user', // just to show a private JWT field,
      exam: {
        name: 'pol',
        surname: 'auladell'
      }
    }

    // generate a signed json web token. By default the signing algorithm is HS256 (HMAC-SHA256), i.e. we will 'sign' with a symmetric secret
    const token = jwt.sign(jwtClaims, jwtSecret)

    // Set the cookie
    // res.cookie('token_cookie' , {token}, {expire : currentDate + 604800})
    res.cookie('token_cookie', token)
    res.redirect('/')
    // console.log(req.cookies['token_cookie'])
    // And let us log a link to the jwt.iot debugger, for easy checking/verifying:   
    console.log(`Token sent. Debug at https://jwt.io/?value=${token}`)
    console.log(`Token secret (for verifying the signature): ${jwtSecret.toString('base64')}`)
    // console.log("Cookies :  ", req.cookies['token_cookie'])
    // res.redirect('/')
  }
)


app.get('/logout',
  (req,res) => {
    res.clearCookie('token_cookie')
    res.send('You have successfully logged out!')
    // res.send('You have logged out')
  }
  )

// app.use(function (req, res) {
//   res.redirect('/')
// })

app.use(function (err, req, res, next) {
  console.error(err.stack)
  res.status(500).send('Something broke!')
})

app.listen(port, () => {
  console.log(`Example app listening at http://localhost:${port}`)
})