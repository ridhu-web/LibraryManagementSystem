const express = require("express");

const { pool } = require("./dbConfig");
const bcrypt = require("bcrypt");
const session = require("express-session");
const flash = require("express-flash");
const passport = require("passport");
const app = express();

const librarianPassportConfig = require("./passportConfig");
const clientPassportConfig = require("./clientPassportConfig");

// Initialize Passport for both user types
librarianPassportConfig(passport);
clientPassportConfig(passport);

const PORT = process.env.PORT || 4000;

app.set("view engine", "ejs");
app.use(express.urlencoded({ extended: false }));

app.use(
  session({
    secret: "secret",

    resave: false,
    saveUninitialized: false,
    cookie: { maxAge: 60000 },
  })
);

app.use(passport.initialize());
app.use(passport.session());

app.use(flash());

app.get("/", (req, res) => {
  res.render("index");
});

app.get("/users/register", (req, res) => {
  res.render("register");
});

app.get("/users/login", (req, res) => {
  res.render("login");
});

app.get("/users/logout", (req, res) => {
  res.render("login");
});

app.get("/librarian/dashboard", (req, res) => {
  res.render("librarianDashboard", { user: req.user.email });
});

app.get("/client/dashboard", (req, res) => {
  res.render("clientDashboard", { user: req.user.email });
});

app.post("/register", async (req, res) => {
  let { email, password, password2, role } = req.body;

  console.log({
    email,
    password,
    password2,
    role,
  });

  let errors = [];
  if (!email || !password || !password2 || !role) {
    errors.push({ message: "Please enter all fields" });
  }

  if (password.length < 6) {
    errors.push({ message: "Password should be at least 6 characters" });
  }

  if (password !== password2) {
    errors.push({ message: "Passwords do not match" });
  }

  if (errors.length > 0) {
    res.render("register", { errors });
  } else {
    // Form validation has passed
    let hashedPassword = await bcrypt.hash(password, 10);
    console.log(hashedPassword);

    // Determine the appropriate tables based on the role
    const userTable = role === "librarian" ? "librarian" : "client";
    const loginTable =
      role === "librarian" ? "librarian_login" : "client_login";

    // Check if the email is registered in the main user table
    pool.query(
      `SELECT * FROM ${userTable} WHERE email = $1`,
      [email],
      (err, result) => {
        if (err) {
          console.error(err);
          return res.render("register", {
            errors: [{ message: "Database error during registration." }],
          });
        }

        if (result.rows.length === 0) {
          errors.push({
            message: `Email not registered as a ${role} in the database.`,
          });
          return res.render("register", { errors });
        }

        // Check if the email is already registered in the login table
        pool.query(
          `SELECT * FROM ${loginTable} WHERE email = $1`,
          [email],
          (err, result) => {
            if (err) {
              console.error(err);
              return res.render("register", {
                errors: [{ message: "Database error during registration." }],
              });
            }

            if (result.rows.length > 0) {
              errors.push({ message: "Email already registered." });
              return res.render("register", { errors });
            } else {
              // Insert into login table if not already registered
              pool.query(
                `INSERT INTO ${loginTable} (email, password_hash) VALUES ($1, $2) RETURNING email, password_hash`,
                [email, hashedPassword],
                (err, result) => {
                  if (err) {
                    console.error(err);
                    throw err;
                  }

                  console.log(result.rows);
                  req.flash(
                    "success_msg",
                    "You are now registered. Please log in"
                  );
                  res.redirect("/users/login");
                }
              );
            }
          }
        );
      }
    );
  }
});

app.post("/users/login", (req, res, next) => {
  // Using the single unified "local" strategy, which should handle both user types
  passport.authenticate("local", (err, user, info) => {
    if (err) {
      return next(err);
    }
    if (!user) {
      req.flash("error_msg", info.message);
      return res.redirect("/users/login");
    }
    req.logIn(user, function (err) {
      if (err) {
        return next(err);
      }
      // Redirect based on role
      // Ensure different dashboards for clients and librarians
      const redirectRoute =
        user.role === "client" ? "/client/dashboard" : "/librarian/dashboard";
      return res.redirect(redirectRoute);
    });
  })(req, res, next);
});

app.post("/clients/register", async (req, res) => {
  const { email, name, ...otherData } = req.body;

  try {
    // Start a database transaction
    await pool.query("BEGIN");

    // Insert the main client information
    const insertClientQuery =
      "INSERT INTO Client (email, name) VALUES ($1, $2)";
    await pool.query(insertClientQuery, [email, name]);

    // Handle multiple addresses
    for (let i = 1; otherData[`streetAddress${i}`]; i++) {
      const addressData = [
        email,
        otherData[`streetAddress${i}`],
        otherData[`city${i}`],
        otherData[`state${i}`],
        otherData[`zipCode${i}`],
      ];
      const insertAddressQuery =
        "INSERT INTO Client_Address (email_address, streetAddress, city, _state_, zipCode) VALUES ($1, $2, $3, $4, $5)";
      await pool.query(insertAddressQuery, addressData);
    }

    // Handle multiple credit cards and their payment addresses
    for (let i = 1; otherData[`cardNumber${i}`]; i++) {
      const cardNumber = otherData[`cardNumber${i}`];
      const cardHolderName = otherData[`cardHolderName${i}`];
      const paymentAddressIndex = otherData["paymentAddress"][i - 1]; // assuming paymentAddress is an array in the form data

      // Insert credit card information
      const insertCardQuery =
        "INSERT INTO Credit_Card (card_no, card_holder_name) VALUES ($1, $2)";
      await pool.query(insertCardQuery, [cardNumber, cardHolderName]);

      // Link credit card to client
      const insertPaymentLinkQuery =
        "INSERT INTO Makes_Payment_By (email_address, card_no) VALUES ($1, $2)";
      await pool.query(insertPaymentLinkQuery, [email, cardNumber]);

      // Map payment address to this card
      const paymentAddress = {
        streetAddress: otherData[`streetAddress${paymentAddressIndex}`],
        city: otherData[`city${paymentAddressIndex}`],
        state: otherData[`state${paymentAddressIndex}`],
        zipCode: otherData[`zipCode${paymentAddressIndex}`],
      };

      const insertPaymentAddressQuery =
        "INSERT INTO Payment_Address (card_no, streetAddress, city, state, zipCode) VALUES ($1, $2, $3, $4, $5)";
      await pool.query(insertPaymentAddressQuery, [
        cardNumber,
        ...Object.values(paymentAddress),
      ]);
    }

    // Commit the transaction
    await pool.query("COMMIT");
    res.send("Client Registered Successfully!");
  } catch (err) {
    // Rollback in case of error
    await pool.query("ROLLBACK");
    console.error("Failed to register client:", err);
    res.status(500).send("Failed to register client.");
  }
});

app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
