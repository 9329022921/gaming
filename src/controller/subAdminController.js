// Import necessary modules and dependencies
const db = require('../config/db'); // Import the database connection module (update the path accordingly)
const User = db.User; // Reference to the User model from the database
const { hashPassword, comparePassword, generateRandomNumber, sendSMS } = require('../helper/middleware'); // Import middleware functions for password hashing, comparison, and random number generation
const jwt = require('jsonwebtoken'); // Import JSON Web Token module for token generation
const secretKey = process.env.JWT_SECRET_KEY; // Secret key for JWT token signing
const CryptoJS = require('crypto-js'); // Import CryptoJS for encryption and decryption (not used in provided code)
const SubAdmin = db.SubAdmin; // Reference to the SubAdmin model from the database
const sendMail = require('../helper/email'); // Import module for sending emails
const Msg = require('../helper/messages'); // Import module for storing messages/constants
const bcrypt = require('bcryptjs'); // Import bcrypt for password hashing and comparison

// Function to verify OTP
exports.otpVerifyfn = async (req, res) => {
    try {
        // Extract phone and OTP from request body
        let { phone, otp } = req.body;

        // Find the sub-admin by phone in the database
        let isExists = await SubAdmin.findOne({ phone: phone });

        // If sub-admin exists
        if (isExists) {
            let code = isExists.code;
            // If the entered OTP matches the stored code
            if (code == otp) {
                return res.status(200).send({
                    status: true,
                    msg: Msg.otpVerified,
                });
            } else {
                // If the entered OTP is wrong, return an error response
                return res.status(200).send({
                    status: false,
                    msg: Msg.wrongOtp,
                });
            }
        } else {
            // If sub-admin does not exist, return a response indicating that
            return res.status(200).send({
                status: false,
                msg: "Invalid number",
            });
        }
    } catch (error) {
        // If an error occurs during OTP verification process, return a server error response
        return res.status(400).send({
            status: false,
            msg: Msg.err,
        });
    }
};

// Function to resend OTP for user verification
exports.resendOtpfn = async (req, res) => {
    try {
        let { phone } = req.body; // Extract phone from request body

        // Check if the sub-admin exists with the provided phone
        let isExists = await SubAdmin.findOne({ phone: phone });

        // If sub-admin exists
        if (isExists) {
            let id = isExists._id; // Get the sub-admin's ID
            const randomNumber = await generateRandomNumber(10000, 20000); // Generate a new random OTP
            const filter = { _id: id }; // Define the filter to find the sub-admin

            // Define the update operation to set the new OTP
            const update = {
                $set: {
                    code: randomNumber
                },
            };

            // Update the sub-admin's OTP in the database
            const check = await SubAdmin.updateOne(filter, update);

            // If OTP update is successful
            if (check && check !== null) {
                // Send the new OTP via SMS
                await sendSMS(phone, randomNumber);
                return res.status(200).send({
                    status: true,
                    msg: Msg.otpSend, // Send success message
                });
            } else {
                return res.status(200).send({
                    status: false,
                    msg: Msg.otpNotSend, // Send error message if OTP update fails
                });
            }
        } else {
            // If sub-admin does not exist with the provided phone
            return res.status(200).send({
                status: false,
                msg: Msg.dataNotFound, // Send message indicating data not found
            });
        }
    } catch (error) {
        // If an error occurs during OTP resend process, return a server error response
        return res.status(400).send({
            status: false,
            msg: Msg.err, // Send error message
        });
    }
};

// Function to handle sub-admin login
exports.subAdminLogin = async (req, res) => {
    try {
        let { phone, password } = req.body; // Extract phone and password from request body

        // Find the sub-admin by phone in the database
        let isExists = await SubAdmin.findOne({ phone: phone });

        // If sub-admin exists and is not null
        if (isExists && isExists !== null) {
            let pass = isExists.password; // Get the sub-admin's hashed password
            let checkPassword = await bcrypt.compare(password, pass); // Compare entered password with hashed password

            // If passwords match
            if (checkPassword) {
                const payload = { id: isExists._id, Role: isExists.role }; // Create payload for JWT token
                const token = jwt.sign(payload, secretKey, { expiresIn: '1h' }); // Generate JWT token with expiration time

                return res.status(200).send({
                    status: true,
                    msg: Msg.loggedIn, // Send success message
                    token: token // Send JWT token
                });
            } else {
                return res.status(200).send({
                    status: false,
                    msg: Msg.inValidPassword, // Send error message if password is invalid
                });
            }
        } else {
            return res.status(200).send({
                status: false,
                msg: Msg.inValidEmail, // Send error message if sub-admin does not exist with provided phone
            });
        }
    } catch (error) {
        // If an error occurs during login process, return a server error response
        return res.status(400).send({
            status: false,
            msg: Msg.err, // Send error message
        });
    }
};

// Function to change sub-admin password
exports.changePassword = async (req, res) => {
    try {
        let id = req.decoded.id; // Get the sub-admin ID from the decoded JWT token
        let { old_password, new_password } = req.body; // Extract old and new passwords from request body

        // Find the sub-admin by ID in the database
        let isExists = await SubAdmin.findOne({ _id: id });

        // If sub-admin exists and is not null
        if (isExists && isExists !== null) {
            let getOldPassword = isExists.password; // Get the sub-admin's hashed old password
            let checkPassword = await bcrypt.compare(old_password, getOldPassword); // Compare entered old password with hashed old password

            // If old password matches
            if (checkPassword) {
                let newPassword = await hashPassword(new_password); // Hash the new password

                // Define filter to find the sub-admin by ID and update operation to set the new password
                const filter = { _id: id };
                const update = {
                    $set: {
                        password: newPassword
                    },
                };

                // Update sub-admin's password in the database
                const check = await SubAdmin.updateOne(filter, update);

                // If password update is successful, return success response
                if (check) {
                    return res.status(200).send({
                        status: true,
                        msg: "Password Change Successfully",
                    });
                } else {
                    // If password update fails, return error response
                    return res.status(200).send({
                        status: false,
                        msg: "Password not Changed",
                    });
                }
            } else {
                // If old password does not match, return error response
                return res.status(200).send({
                    status: false,
                    msg: "Invalid password",
                });
            }
        } else {
            // If sub-admin does not exist with the provided ID, return error response
            return res.status(200).send({
                status: false,
                msg: "Sub-admin Not Exists",
            });
        }
    } catch (error) {
        // If an error occurs during password change process, return a server error response
        return res.status(400).send({
            status: false,
            msg: "Something went wrong"
        });
    }
};


// Function to send OTP for password reset
exports.forgetPasswordSendOtpFn = async (req, res) => {
    try {
        let { phone } = req.body; // Extract phone number from request body

        // Find the sub-admin by phone number in the database
        let isSubAdminExists = await SubAdmin.findOne({ phone: phone });

        // If sub-admin exists with the provided phone number
        if (isSubAdminExists) {
            const randomNumber = await generateRandomNumber(10000, 20000); // Generate a random OTP
            const filter = { phone: phone }; // Define filter to find the sub-admin by phone number

            // Define update operation to set the new OTP
            const update = {
                $set: {
                    code: randomNumber
                },
            };

            // Update sub-admin's OTP in the database
            const check = await SubAdmin.updateOne(filter, update);

            // If OTP update is successful
            if (check) {
                await sendSMS(phone, randomNumber); // Send the OTP via SMS
                return res.status(200).send({
                    status: true,
                    msg: "OTP sent successfully",
                });
            } else {
                return res.status(200).send({
                    status: false,
                    msg: "Failed to send OTP",
                });
            }
        } else {
            // If sub-admin does not exist with the provided phone number, return error response
            return res.status(200).send({
                status: false,
                msg: "Sub-admin not found"
            });
        }
    } catch (error) {
        // If an error occurs during OTP sending process, return a server error response
        return res.status(400).send({
            status: false,
            msg: "Something went wrong"
        });
    }
}

// Function to reset sub-admin password using OTP verification
exports.forgetPasswordFn = async (req, res) => {
    try {
        let { phone, otp, password } = req.body; // Extract phone number, OTP, and new password from request body

        // Find the sub-admin by phone number in the database
        let isExists = await SubAdmin.findOne({ phone: phone });

        // If sub-admin exists with the provided phone number
        if (isExists) {
            let newPassword = await hashPassword(password); // Hash the new password

            // Define filter to find the sub-admin by phone number and update operation to set the new password
            const filter = { phone: phone };
            const update = {
                $set: {
                    password: newPassword
                },
            };

            // Update sub-admin's password in the database
            const check = await SubAdmin.updateOne(filter, update);

            // If password update is successful, return success response
            if (check) {
                return res.status(200).send({
                    status: true,
                    msg: "Your Password Has Been Reset Successfully",
                });
            } else {
                // If password update fails, return error response
                return res.status(200).send({
                    status: false,
                    msg: "Failed to reset password",
                });
            }
        } else {
            // If sub-admin does not exist with the provided phone number, return error response
            return res.status(200).send({
                status: false,
                msg: "Sub-admin not found"
            });
        }
    } catch (error) {
        // If an error occurs during password reset process, return a server error response
        return res.status(400).send({
            status: false,
            msg: "Something went wrong"
        });
    }
}


// Function to send OTP for password reset
exports.forgetPasswordSendOtpFn = async (req, res) => {
    try {
        let { phone } = req.body; // Extract phone number from request body

        // Find the sub-admin by phone number in the database
        let isSubAdminExists = await SubAdmin.findOne({ phone: phone });

        // If sub-admin exists with the provided phone number
        if (isSubAdminExists) {
            const randomNumber = await generateRandomNumber(10000, 20000); // Generate a random OTP
            const filter = { phone: phone }; // Define filter to find the sub-admin by phone number

            // Define update operation to set the new OTP
            const update = {
                $set: {
                    code: randomNumber
                },
            };

            // Update sub-admin's OTP in the database
            const check = await SubAdmin.updateOne(filter, update);

            // If OTP update is successful
            if (check) {
                await sendSMS(phone, randomNumber); // Send the OTP via SMS
                return res.status(200).send({
                    status: true,
                    msg: "OTP sent successfully",
                });
            } else {
                return res.status(200).send({
                    status: false,
                    msg: "Failed to send OTP",
                });
            }
        } else {
            // If sub-admin does not exist with the provided phone number, return error response
            return res.status(200).send({
                status: false,
                msg: "Sub-admin not found"
            });
        }
    } catch (error) {
        // If an error occurs during OTP sending process, return a server error response
        return res.status(400).send({
            status: false,
            msg: "Something went wrong"
        });
    }
}






