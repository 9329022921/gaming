// Importing necessary functions from the express-validator library
const { body, validationResult } = require('express-validator');

// Validation rules for user registration
const validateUser = [
    body('name').notEmpty().withMessage('Username must be required'), // Username should not be empty
    body('number').notEmpty().isLength({ min: 10 }).withMessage('Phone number must be ten'), // Phone number should not be empty and must be 10 digits long
    body('email').isEmail().withMessage('Email must be required'), // Email should be a valid email format
    body('password').notEmpty().isLength({ min: 8 }).withMessage('Password should be eight'), // Password should not be empty and must be at least 8 characters long
    // You can add more validation rules for other fields as needed
];

// Validation rules for user login
const validateLogin = [
    body('phone').notEmpty().isLength({ min: 10 }).withMessage('number must be required'), // Email should be a valid email format
    body('password').notEmpty().isLength({ min: 8 }).withMessage('Password should be eight'), // Password should not be empty and must be at least 8 characters long
    // Add more validation rules as needed
];

// Validation rules for note creation
const noteValidation = [
    body('title').notEmpty().withMessage('Title must be required'), // Title should not be empty
    body('description').notEmpty().withMessage('Description should be required'), // Description should not be empty
];

// Middleware function to handle validation errors
const handleValidationErrors = (req, res, next) => {
    const errors = validationResult(req);
    // If there are validation errors, return a 400 Bad Request response with the first error message
    if (!errors.isEmpty()) {
        return res.status(400).send({
            msg: errors.errors[0].msg
        });
    }
    // If there are no validation errors, move to the next middleware or route handler
    next();
};

// Exporting validation rules and error handling middleware
module.exports = {
    validateUser,
    validateLogin,
    noteValidation,
    handleValidationErrors
};
