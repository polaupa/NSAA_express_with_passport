const express = require('express')
const logger = require('morgan')
const passport = require('passport')

var radius = require('radius');
const https = require('https');
const fs = require('fs');
var dgram = require('dgram');

const tlsServerKey = fs.readFileSync('./tls/webserver.key.pem');
const tlsServerCrt = fs.readFileSync('./tls/webserver.crt.pem');

const LocalStrategy = require('passport-local').Strategy
var JwtStrategy = require('passport-jwt').Strategy
const OAuth2Strategy = require('passport-oauth2').Strategy
const GitHubStrategy = require('passport-github2').Strategy

const jwt = require('jsonwebtoken')
const cookieParser = require('cookie-parser');
const jwtSecret = require('crypto').randomBytes(16) // 16*8= 256 random bits 

const bcrypt = require('bcrypt');
const saltRounds = 8;

const fortune = require('fortune-teller')

const port = 443
const app = express()

const {GIT_CLIENT_ID} = require('./config.js')
const {GIT_CLIENT_SECRET} = require('./config.js')
const {RADIUS_SECRET} = require('./config.js')

const RADIUS_PORT = 1812
const RADIUS_IP = "10.0.2.15"

const httpsOptions = {
  key: tlsServerKey,
  cert: tlsServerCrt
};

var server = https.createServer(httpsOptions, app);

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
    if(jwt_payload) {
      return done(null, jwt_payload.sub)
    }
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

passport.use('radius', new LocalStrategy(
  {
    usernameField: 'username',
    passwordField: 'password',
    session: false // we are storing a JWT in the cookie with all the required session data. The server is session-less
  },
  function (username, password, done) {
    innerIdentity = username.split("@")
    innerIdentity = innerIdentity[0]

    var request_packet = radius.encode({
      code: "Access-Request",
      secret: RADIUS_SECRET,
      attributes: [
        ['NAS-IP-Address', RADIUS_IP],
        ['User-Name', username],
        ['User-Password', password],
      ]
    });

    var client = dgram.createSocket("udp4");

    client.on("message", function (msg, rinfo) {
      // var code, username, password, packet;
      var response = radius.decode({packet: msg, secret: RADIUS_SECRET});
      
      console.log('Access-Request for ' + username);
    
      var valid_response = radius.verify_response({
        response: msg, //raw packet we have received
        request: request_packet, //raw packet we have sent
        secret: RADIUS_SECRET
      });

      if (valid_response && response.code == "Access-Accept") {
        console.log('Got valid response (' + response.code + ') for packet id ' + response.identifier);
        console.log("Reply Message from RADIUS:" + response.attributes["Reply-Message"])
        user = {username:innerIdentity}
        return done(null, user)
      }
      console.error('Got invalid response (' + response.code + ') for packet id ' + response.identifier);
      return done(null, false)
    });

    client.send(request_packet, 0, request_packet.length, RADIUS_PORT, RADIUS_IP);

  }
))

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
  authorizationURL: 'https://github.com/login/oauth/authorize',
  tokenURL: 'https://github.com/login/oauth/access_token',
  clientID: GIT_CLIENT_ID,
  clientSecret: GIT_CLIENT_SECRET,
  callbackURL: "http://localhost:3000/oauth2/token",
  scope: "read:user"
},
function(accessToken, refreshToken, profile, done) {
  console.log(profile)
  user = {githubId: profile.id, username:profile.username}
  return done(null, user)
}
))

passport.use(new GitHubStrategy({
  clientID: GIT_CLIENT_ID,
  clientSecret: GIT_CLIENT_SECRET,
  callbackURL: "http://localhost:3000/oauth2/token"
},
function(accessToken, refreshToken, profile, done) {
  user = {githubId: profile.id, username:profile.username}
  return done(null, user)
}
))

/*-------------------------------------------------------*/

app.use(express.urlencoded({ extended: true })) // needed to retrieve html form fields
app.use(passport.initialize()) // we load the passport auth middleware to our express application. It should be loaded before any route.

app.get('/',
  passport.authenticate('jwt', { failureRedirect: '/radius', session: false }),
  (req, res) => {
    res.send(fortune.fortune())
  }
)

app.get('/auth/github',
  passport.authenticate('oauth2', { scope: [ 'user:email' ] }),
  (req, res) => {
    res.redirect('/')
  }
)

app.get('/oauth2/token',
  passport.authenticate('oauth2', { failureRedirect: '/login' , session: false}),
  createCookie,
  (req, res) => {
    res.redirect('/')
  },

)

app.get('/login',
  (req, res) => {
    res.sendFile('login.html', { root: __dirname })
  }
)

app.post('/login',
  passport.authenticate('local', { failureRedirect: '/login', session: false }),
  createCookie,
  (req, res, next) => {
    res.redirect('/')
  }
)

app.get('/radius',
  (req, res) => {
    res.sendFile('radius.html', { root: __dirname })
  }
)

app.post('/radius',
  passport.authenticate('radius', { failureRedirect: '/radius', session: false }),
  createCookie,
  (req, res, next) => {
    res.redirect('/')
  }
)

app.get('/logout',
  (req,res) => {
    res.clearCookie('token_cookie')
    res.send('You have successfully logged out!')
    // res.send('You have logged out')
  }
  )

app.use(function (err, req, res, next) {
  console.error(err.stack)
  res.status(500).send('Something broke!')
})

server.listen(port, () => {
  console.log(`Example app listening at http://10.0.2.5:${port}`)
})

server.on('listening', onListening);

/**
 * Event listener for HTTP server "listening" event.
 */
function onListening() {
    const addr = server.address();
    const bind = typeof addr === 'string'
        ? 'pipe ' + addr
        : 'port ' + addr.port;
    console.log('Listening on ' + bind);
}

/*-------------------------------------------------------*/

function createCookie(req,res,next){
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
  const token = jwt.sign(jwtClaims, jwtSecret)

  res.cookie('token_cookie', token)

  console.log(`Token sent. Debug at https://jwt.io/?value=${token}`)
  // console.log(`Token secret (for verifying the signature): ${jwtSecret.toString('base64')}`)
  next()
}
