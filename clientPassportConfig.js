const LocalStrategy = require("passport-local").Strategy;
const { pool } = require("./dbConfig");
const bcrypt = require("bcrypt");

function initialize(passport) {
  const authenticateClient = (req, email, password, done) => {
    pool.query(
      `SELECT * FROM client_login WHERE email = $1`,
      [email],
      (err, results) => {
        if (err) {
          return done(err);
        }

        if (results.rows.length > 0) {
          const user = results.rows[0];

          bcrypt.compare(password, user.password_hash, (err, isMatch) => {
            if (err) {
              return done(err);
            }
            if (isMatch) {
              user.role = "client"; // Adding role to the user object for use in routing decisions
              return done(null, user);
            } else {
              return done(null, false, { message: "Password is incorrect" });
            }
          });
        } else {
          return done(null, false, {
            message: "No client with that email address",
          });
        }
      }
    );
  };

  passport.use(
    "local-client",
    new LocalStrategy(
      {
        usernameField: "email",
        passwordField: "password",
        passReqToCallback: true, // This allows us to access the request object in the callback
      },
      authenticateClient
    )
  );

  passport.serializeUser((user, done) => {
    done(null, user.email); // Serializes user email into the session
  });

  passport.deserializeUser((email, done) => {
    // This function retrieves user details from the database using the email serialized in the session.
    pool.query(
      `SELECT * FROM client_login WHERE email = $1`,
      [email],
      (err, results) => {
        if (err) {
          return done(err);
        }
        return done(null, results.rows[0]); // Attaches the full user record to the request object as req.user
      }
    );
  });
}

module.exports = initialize;
