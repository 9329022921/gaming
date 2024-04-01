// Import required module
const mongoose = require('mongoose');

// Define async function to connect to MongoDB
const connectDB = async () => {
  try {
    // Attempt to connect to MongoDB using the provided URL and options
    await mongoose.connect(process.env.MONGOURL, {
      useNewUrlParser: true, // Use the new URL parser
      useUnifiedTopology: true, // Use the new server discovery and monitoring engine
    });
    // Log a success message if connected to MongoDB
    console.log('Connected to MongoDB');
  } catch (error) {
    // Log an error message if connection fails
    console.error('Error connecting to MongoDB:', error);
  }
};

// Call the connectDB function to establish the connection to MongoDB
connectDB();

// Export database models for use in other parts of the application
module.exports = {
  Admin: require('../model/admin.schema'), // Export the Admin model from admin.schema file
  SubAdmin: require('../model/subAdmin.schema'), // Export the User model from user.schema file
  User: require('../model/user.schema')
};
