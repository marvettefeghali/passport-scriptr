# passport-scriptr

[Passport](https://github.com/marvettefeghali/passport) strategy for authenticating
with [Scriptr](https://scriptr.io) using the OAuth 2.0 API.

## Install

    $ npm install passport-scriptr

## Usage

#### Configure Strategy

The Scriptr authentication strategy authenticates users using a Scriptr
account and OAuth 2.0 tokens.  The strategy requires a `verify` callback, which
accepts these credentials and calls `done` , as well as
`options` specifying a client ID, and callback URL.

    passport.use(new ScriptrStrategy({
    	clientID: "",
    	scopes: "execute list manage",
        callbackURL : "",
        failureRedirect : ""
      },
      function(req, accessToken, refreshToken, params, profile, done) {
        	this.saveInfo(req, accessToken, refreshToken, params, profile, done);
      });
    ));

#### Authenticate Requests

Use `passport.authorize()`, specifying the `'scriptr'` strategy, to
authenticate requests.

For example, as route middleware in an [Express](http://expressjs.com/)
application:

    app.get('/auth/scriptr',
      passport.authorize('scriptr'));

    app.get('/auth/scriptr/callback', 
      passport.authorize('scriptr', { failureRedirect: '/login' }),
      function(req, res) {
        // Successful authentication, redirect home.
        res.redirect('/');
      });

## Thanks

  - [Jared Hanson](http://github.com/jaredhanson)
  - [Michael Pearson](http://github.com/mjpearson)
## License

[The MIT License](http://opensource.org/licenses/MIT)

Copyright (c) 2015 [Marvette Feghali](https://github.com/marvettefeghali/)
