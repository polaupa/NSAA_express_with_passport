# Using Express with Passport

## Exchange the JWT using cookies
For this challenge,  `cookie-parser` package is needed.

In `app.post` we will create a cookie and store the token:

```javascript
res.cookie('token_cookie', token, {expire : currentDate + 604800})
```
We setted an expiry date of the token of 1 week (604800 seconds).   

In the same method, we will redirect the user to the home webpage after it logged in, and the cookie is stored:

```javascript
res.redirect('/')
```

## Create the fortune-teller endpoint

The idea of this challenge is:
1. Change the home route (`'/'`) with `fortune-teller` package.
2. To only allow the user to see its fortune teller if it has been authenticated with JWT.

The first step is to create the Passport JWT Strategy:
```javascript
passport.use('jwt', new JwtStrategy({
  jwtFromRequest: cookieExtractor,
  secretOrKey: jwtSecret
},
  function (jwt_payload, done) {
    if (jwt_payload.sub === 'walrus') {
      const user = {
        username: 'walrus',
        description: 'the only user that deservers to contact the fortune teller'
      }
      return done(null, user);
    }
    else {
      return done(null, false);
    }
  }
));
```

This strategy has our secret, and the cookie we stored earlier as inputs. To extract the cookie, we designed this funcion:

```javascript
var cookieExtractor = function (req) {
  var token = null;
  if (req && req.cookies) {
    token = req.cookies.token_cookie;
  }
  return token;
};
```

Besides, in the strategy, we only take into accont the case that the username is walrus. Later we will change it.

Finally, to only grant access to `'/'` to the users that had successfully logged in, we have to change the get of that route:

```javascript
app.get('/',
  passport.authenticate('jwt', { failureRedirect: '/login', session: false }),
  (req, res) => {
    res.send(fortune.fortune())
  }
```

## Add a logout endpoint

This exercice consists in creating a logout route, to allow the user to log out the session.

To do it, we will create this new route, and then we will clear the token cookie:

```javascript
app.get('/logout',
  (req,res) => {
    res.clearCookie('token_cookie')
    res.send('You have successfully logged out!')
  }
  )
```

## Add bcrypt or scrypt to the login process

In this last challenge, we want to grant access to the users stored in a database, `users.json`. 

This database must contain the username, and the hashed password. For the hash function, we will use `bcrypt`.

To generate the hash, we have used: 
```javascript
bcrypt.hash(password, saltRounds, 
  (err, hash) => {
    console.log(hash)
  })
```

Once we have our database created, we will modify the passport functions.

On the one hand, for `LocalStrategy`:

```javascript
passport.use('local', new LocalStrategy(
  {
    usernameField: 'username',
    passwordField: 'password',
    session: false
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
```

And on the other hand, for `JwtStrategy`:

```javascript
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
```