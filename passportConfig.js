const LocalStrategy = require("passport-local").Strategy;
const { pool } = require("./dbConfig");
const bcrypt = require("bcrypt");

function initialize(passport) {
  passport.use(
    "local",
    new LocalStrategy(
      {
        usernameField: "email",
        passwordField: "password",
        passReqToCallback: true,
      },
      async (req, email, password, done) => {
        try {
          // Determine the table to query based on the user type provided
          const userType = req.body.role; // This should be included in your login form
          const table =
            userType === "client" ? "client_login" : "librarian_login";

          console.log("obtained", email, password, userType);

          const result = await pool.query(
            `SELECT * FROM ${table} WHERE email = $1`,
            [email]
          );
          const user = result.rows[0];

          if (!user) {
            return done(null, false, {
              message: `No ${userType} found with that email.`,
            });
          }

          const isMatch = await bcrypt.compare(password, user.password_hash);

          if (!isMatch) {
            return done(null, false, { message: "Password is incorrect" });
          }

          user.role = userType; // Attach role to user object
          return done(null, user);
        } catch (err) {
          console.error(err);
          return done(err);
        }
      }
    )
  );

  // Serialize user into the session
  passport.serializeUser((user, done) =>
    done(null, { id: user.email, role: user.role })
  );

  // Deserialize user from the session
  passport.deserializeUser((obj, done) => {
    const table = obj.role === "client" ? "client_login" : "librarian_login";
    pool.query(
      `SELECT * FROM ${table} WHERE email = $1`,
      [obj.id],
      (err, results) => {
        if (err) {
          return done(err);
        }
        const user = results.rows[0];
        user.role = obj.role; // Ensure role is still attached
        return done(null, user);
      }
    );
  });
}

module.exports = initialize;
