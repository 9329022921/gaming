// Importing the bcryptjs library for password hashing
const bcrypt = require('bcryptjs');
// Importing the jsonwebtoken library for token generation and verification
const jwt = require('jsonwebtoken');
const accountSid = process.env.TWILIO_ACCOUNT_SID;
const authToken = process.env.TWILIO_AUTH_TOKEN;

const client = require('twilio')(accountSid, authToken);

// Function to hash the given password using bcrypt
exports.hashPassword = async (password, saltRounds = 10) => {
    try {
        // Generate a salt
        const salt = await bcrypt.genSalt(saltRounds);
        // Hash the password using the generated salt
        return await bcrypt.hash(password, salt);
    } catch (error) {
        console.log(error); // Log any error that occurs during the process
    }
    // Return null if an error occurs
    return null;
}

// Function to compare the given password with a hash using bcrypt
exports.comparePassword = async (pass, hash) => {
    try {
        // Compare the provided password with the hash
        const match = await bcrypt.compare(pass.toString(), hash);
        if (match) {
            return match; // If passwords match, return true
            // (Optionally, you might want to proceed with login logic here)
        }
    } catch (error) {
        console.log(error); // Log any error that occurs during the process
    }
    // Return false if an error occurs or if passwords don't match
    return false;
}

// Middleware function to authenticate a token
exports.authenticateToken = async (req, res, next) => {
    // Get the authorization token from the request header
    const authToken = req.header('Authorization');
    // If no token is provided, return a 401 Unauthorized response
    if (!authToken) return res.status(401).send('Please provide a token');
    // Extract the token from the authorization header (assuming it's prefixed with 'Bearer')
    let token = authToken.split(' ').slice(-1)[0];
    try {
        // Verify the token using the secret key and decode it
        const decoded = jwt.verify(token, process.env.JWT_SECRET_KEY);
        // Attach the decoded token to the request object for later use
        req.decoded = decoded;
        // Move to the next middleware or route handler
        next();
    } catch (error) {
        // If token verification fails, return a 403 Forbidden response
        res.status(403).send('Invalid token');
    }
}

// Function to generate a random number within the specified range
exports.generateRandomNumber = async (min, max) => {
    // Generate and return a random number within the specified range
    return Math.floor(Math.random() * (max - min + 1)) + min;
}

exports.sendSMS = async (phone, otp) => {
    let msgOptions = { from: '+19523143917', body: `your otp is ${otp}`, to: `+91${phone}` }
    try {
        let data = await client.messages.create(msgOptions)
        return data
    } catch (error) {
        console.log('====================');
        return error
    }
}
