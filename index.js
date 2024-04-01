// Import required modules
var express = require('express'); // Express framework for building web applications
var bodyParser = require('body-parser'); // Middleware to parse incoming request bodies
var cors = require('cors'); // Middleware for enabling Cross-Origin Resource Sharing (CORS)
require('dotenv').config(); // Load environment variables from .env file
const route = require('./src/router'); // Import custom router module

var app = express(); // Create an instance of Express application

// Middleware setup
app.use(cors()); // Enable CORS for all routes
app.use(bodyParser.urlencoded({ extended: false })); // Parse URL-encoded request bodies
app.use(bodyParser.json()); // Parse JSON request bodies

// Define routes
app.use('/api/v1', route); // Mount the custom router at /api/v1

// Start the server
let port = process.env.PORT; // Get port number from environment variables
app.listen(port, () => {
    console.log(`Server started at http://localhost:${port}`); // Log server start message with port number
});
