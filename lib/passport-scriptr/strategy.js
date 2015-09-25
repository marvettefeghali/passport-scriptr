/**
 * Module dependencies.
 */
var util = require('util'), OAuth2Strategy = require('passport-oauth').OAuth2Strategy, 
	InternalOAuthError = require('passport-oauth').InternalOAuthError;

/**
 * `Strategy` constructor.
 * 
 * The Scriptr authentication strategy authenticates requests by delegating to
 * Scriptr using the OAuth 2.0 protocol WITH IMPLICIT GRANT TYPE.
 * 
 * Applications must supply a `verify` callback which accepts an `accessToken`,
 * `refreshToken` and service-specific `profile`, and then calls the `done`
 * callback supplying a `user`, which should be set to `false` if the
 * credentials are not valid. If an exception occured, `err` should be set.
 * 
 * Options: - `clientID` your Scriptr application's client id - `callbackURL`
 * URL to which Scriptr will redirect the user after granting authorization -
 * `scope` array of permission scopes to request. valid scopes include:
 * 'manage', 'list', 'execute'.
 * 
 * Examples:
 * 
 * passport.use(new ScriptrStrategy({ clientID: '123-456-789', callbackURL:
 * 'https://www.example.net/auth/scriptr/callback', scope: 'list manage execute' },
 * function(accessToken, refreshToken, profile, done) { User.findOrCreate(...,
 * function (err, user) { done(err, user); }); } ));
 * 
 * @param {Object}
 *            options
 * @param {Function}
 *            verify
 * @api public
 */
function Strategy(options, verify) {
	options = options || {};
	options.authorizationURL = options.authorizationURL
			|| 'https://www.scriptr.io/authorize';
	options.tokenURL = options.authorizationURL; //In implicit mode, access token is acquired during authorization 
	options.skipUserProfile = true;
	options.scopeSeparator = ' ';
	
	//In Implicit Grant Type, clientSecret is not used, we will set it to NOT_A_SECRET
	 options.clientSecret = "NOT_A_SECRET";

	OAuth2Strategy.call(this, options, verify);
	this.name = 'scriptr';
}

/**
 * Inherit from `OAuth2Strategy`.
 */
util.inherits(Strategy, OAuth2Strategy);

/**
 * Override the OAuth2Strategy Default to cater for IMPLICIT grant type
 */
Strategy.prototype.authenticate = function(req, options) {
	options = options || {};
	var self = this;

	if (req.query && req.query.error) {
		// TODO: Error information pertaining to OAuth 2.0 flows is encoded in
		// the
		// query parameters, and should be propagated to the application.
		return this.fail();
	}

	var callbackURL = options.callbackURL || this._callbackURL;
	if (callbackURL) {
		var parsed = url.parse(callbackURL);
		if (!parsed.protocol) {
			// The callback URL is relative, resolve a fully qualified URL from
			// the
			// URL of the originating request.
			callbackURL = url.resolve(utils.originalURL(req), callbackURL);
		}
	}

	if (req.query && req.query.access_token) {
		var access_token = req.query.access_token;

		(function(req, err, accessToken, refreshToken, params) {
			if (err) {
				return self.error(new InternalOAuthError(
						'failed to obtain access token', err));
			}

			self._loadUserProfile(accessToken, function(err, profile) {
				if (err) {
					return self.error(err);
				}
				;
				function verified(err, user, info) {
					if (err) {
						return self.error(err);
					}
					if (!user) {
						return self.fail(info);
					}
					self.success(user, info);
				}

				if (self._passReqToCallback) {
					var arity = self._verify.length;
					if (arity == 6) {
						self._verify(req, accessToken, refreshToken, params,
								profile, verified);
					} else { // arity == 5
						self._verify(req, accessToken, refreshToken, profile,
								verified);
					}
				} else {
					var arity = self._verify.length;
					if (arity == 5) {
						self._verify(accessToken, refreshToken, params,
								profile, verified);
					} else { // arity == 4
						self._verify(accessToken, refreshToken, profile,
								verified);
					}
				}
			});

		})(req, req.query.error, req.query.access_token,
				req.query.refres_token, req.query);
	} else {
		var params = this.authorizationParams(options);
		params['response_type'] = 'token'; //Implicit OAUTH2 Acquire token
		params['redirect_uri'] = callbackURL;
		var scope = options.scope || this._scope;
		if (scope) {
			if (Array.isArray(scope)) {
				scope = scope.join(this._scopeSeparator);
			}
			params.scope = scope;
		}
		var state = options.state;
		if (state) {
			params.state = state;
		}

		var location = this._oauth2.getAuthorizeUrl(params);
		this.redirect(location);
	}
};

/**
 * Expose `Strategy`.
 */
module.exports = Strategy;
