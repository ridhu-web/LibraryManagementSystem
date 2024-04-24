require("dotenv").config();

const { Pool } = require("pg"); // Import Pool from pg
const isProduction = process.env.NODE_ENV === "production"; // Check if the environment is production
const connectionString = `postgresql://${process.env.DB_USER}:${process.env.DB_PASSWORD}@${process.env.DB_HOST}:${process.env.DB_PORT}/${process.env.DB_DATABASE}`; // Set the connection string

const pool = new Pool({
  connectionString: isProduction ? process.env.DATABASE_URL : connectionString, // Set the connection string based on the environment
});

module.exports = { pool }; // Export the pool object
