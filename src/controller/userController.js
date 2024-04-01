// Import necessary modules and dependencies
const db = require('../config/db'); // Import the database connection module (update the path accordingly)
const User = db.User; // Reference to the User model from the database
const { hashPassword, comparePassword, generateRandomNumber, sendSMS } = require('../helper/middleware'); // Import middleware functions for password hashing, comparison, and random number generation
const jwt = require('jsonwebtoken'); // Import JSON Web Token module for token generation
const secretKey = process.env.JWT_SECRET_KEY; // Secret key for JWT token signing
const CryptoJS = require('crypto-js'); // Import CryptoJS for encryption and decryption (not used in provided code)
const sendMail = require('../helper/email'); // Import module for sending emails
const Msg = require('../helper/messages'); // Import module for storing messages/constants

const bcrypt = require('bcryptjs'); // Import bcrypt for password hashing and comparison

// Function to register a new user
exports.getOtp = async (req, res) => {
    try {
        // Extract user details from request body
        let { name, phone, password } = req.body;

        // Check if the user already exists in the database
        let isUserExists = await User.findOne({ phone: phone });
        if (isUserExists) {
            let isVerified = isUserExists.isVerified
            if (isVerified == false) {
                let newPassword = await hashPassword(password);
                // Generate a random number for verification code
                const randomNumber = await generateRandomNumber(10000, 20000);
                const filter = { phone: phone };
                const update = {
                    $set: {
                        name: name,
                        phone: phone,
                        password: newPassword,
                        code: randomNumber
                    },
                };

                // Update user's profile in the database
                let data = await User.updateOne(filter, update);
                if (data) {
                    await sendSMS(phone, randomNumber)
                    return res.status(200).send({
                        status: true,
                        msg: Msg.otpSend,
                        data: data
                    });
                } else {
                    return res.status(200).send({
                        status: false,
                        msg: Msg.otpNotSend,
                        data: data
                    });
                }
            } else {
                return res.status(200).send({
                    status: true,
                    msg: Msg.phoneRegisterError,
                });
            }
        } else {
            // Hash the password using bcrypt
            let newPassword = await hashPassword(password);
            // Generate a random number for verification code
            const randomNumber = await generateRandomNumber(10000, 20000);
            // Create an object to store user data
            let obj = {
                name: name,
                phone: phone,
                password: newPassword,
                code: randomNumber
            };
            // Insert the user data into the database
            let data = await User.insertMany(obj);

            // If data insertion is successful, send a verification email
            if (data) {
                await sendSMS(phone, randomNumber)
                return res.status(200).send({
                    status: true,
                    msg: Msg.otpSend,
                    data: data
                });
            } else {
                // If data insertion fails, return an error response
                return res.status(200).send({
                    status: false,
                    msg: Msg.otpNotSend
                });
            }
        }
    } catch (error) {
        // If an error occurs during registration process, return a server error response
        return res.status(400).send({
            status: false,
            msg: Msg.err
        });
    }
}

// Function to verify OTP for user registration
exports.otpVerifyfn = async (req, res) => {
    try {
        // Extract phone number and OTP from request body
        let { phone, otp } = req.body;

        // Find the user by phone number in the database
        let isUserExists = await User.findOne({ phone: phone });

        // If user exists
        if (isUserExists) {
            let isVerified = isUserExists.isVerified;
            // If user is not already verified
            if (isVerified == false) {
                let code = isUserExists.code;
                // If the entered OTP matches the stored code
                if (code == otp) {
                    // Update user's verification status to true
                    const filter = { phone: phone };
                    const update = {
                        $set: {
                            isVerified: true
                        },
                    };
                    const check = await User.updateOne(filter, update);
                    // Return a success response
                    return res.status(200).send({
                        status: true,
                        msg: Msg.registerSuccess,
                    })
                } else {
                    // If the entered OTP is wrong, return an error response
                    return res.status(200).send({
                        status: false,
                        msg: Msg.wrongOtp,
                    })
                }
            } else {
                // If the user is already verified, return a response indicating that
                return res.status(200).send({
                    status: false,
                    msg: Msg.allReadyOtpVerified,
                })
            }
        } else {
            // If user does not exist, return a response indicating that
            return res.status(200).send({
                status: false,
                msg: Msg.inValidPhone
            })
        }
    } catch (error) {
        // If an error occurs during OTP verification process, return a server error response
        return res.status(400).send({
            status: false,
            msg: Msg.err
        })
    }
}

// Function to resend OTP for user verification
exports.resendOtpfn = async (req, res) => {
    try {
        let { phone } = req.body; // Extract phone number from request body

        // Check if the user exists with the provided phone number
        let isUserExists = await User.findOne({ phone: phone });

        // If user exists
        if (isUserExists) {
            let isVerified = isUserExists.isVerified
            if (isVerified == false) {
                let id = isUserExists._id; // Get the user's ID
                const randomNumber = await generateRandomNumber(10000, 20000); // Generate a new random OTP
                const filter = { _id: id }; // Define the filter to find the user

                // Define the update operation to set the new OTP
                const update = {
                    $set: {
                        code: randomNumber
                    },
                };

                // Update the user's OTP in the database
                const check = await User.updateOne(filter, update);

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
                return res.status(200).send({
                    status: false,
                    msg: Msg.phoneRegisterError, // Send error message if user is already verified
                });
            }
        } else {
            // If user does not exist with the provided phone number
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
}


// Function to handle user login
exports.userLogin = async (req, res) => {
    try {
        let { phone, password } = req.body; // Extract phone and password from request body

        // Find the user by phone number in the database
        let isUserExists = await User.findOne({ phone: phone });

        // If user exists and is not null
        if (isUserExists && isUserExists !== null) {
            if (isUserExists.isVerified == true) {
                let pass = isUserExists.password; // Get the user's hashed password
                let checkPassword = await bcrypt.compare(password, pass); // Compare entered password with hashed password

                // If passwords match
                if (checkPassword) {
                    const payload = { userId: isUserExists._id }; // Create payload for JWT token
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
                    msg: Msg.phoneNotRegister, // Send error message if phone is not registered
                });
            }
        } else {
            return res.status(200).send({
                status: false,
                msg: Msg.phoneNotRegister, // Send error message if user does not exist with provided phone number
            });
        }
    } catch (error) {
        // If an error occurs during login process, return a server error response
        return res.status(400).send({
            status: false,
            msg: Msg.err, // Send error message
        });
    }
}

// Function to change user password
exports.changePassword = async (req, res) => {
    try {
        let userId = req.decoded.userId; // Get the user ID from the decoded JWT token
        let { old_password, new_password } = req.body; // Extract old and new passwords from request body

        // Find the user by ID in the database
        let isUserExists = await User.findOne({ _id: userId });

        // If user exists and is not null
        if (isUserExists && isUserExists !== null) {
            let getOldPassword = isUserExists.password; // Get the user's hashed old password
            let checkPassword = await bcrypt.compare(old_password, getOldPassword); // Compare entered old password with hashed old password

            // If old password matches
            if (checkPassword) {
                let newPassword = await hashPassword(new_password); // Hash the new password

                // Define filter to find the user by ID and update operation to set the new password
                const filter = { _id: userId };
                const update = {
                    $set: {
                        password: newPassword
                    },
                };

                // Update user's password in the database
                const check = await User.updateOne(filter, update);

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
                        msg: "Password not Change",
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
            // If user does not exist with the provided ID, return error response
            return res.status(200).send({
                status: false,
                msg: "User Not Exists",
            });
        }
    } catch (error) {
        // If an error occurs during password change process, return a server error response
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

        // Find the user by phone number in the database
        let isUserExists = await User.findOne({ phone: phone });

        // If user exists with the provided phone number
        if (isUserExists) {
            const randomNumber = await generateRandomNumber(10000, 20000); // Generate a random OTP
            const filter = { phone: phone }; // Define filter to find the user by phone number

            // Define update operation to set the new OTP
            const update = {
                $set: {
                    code: randomNumber
                },
            };

            // Update user's OTP in the database
            const check = await User.updateOne(filter, update);

            // If OTP update is successful
            if (check) {
                // Send the OTP via SMS
                await sendSMS(phone, randomNumber);
                return res.status(200).send({
                    status: true,
                    msg: "OTP sent successfully",
                });
            }
        } else {
            // If user does not exist with the provided phone number, return error response
            return res.status(200).send({
                status: false,
                msg: "User not found"
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

// Function to reset user password using OTP verification
exports.forgetPasswordFn = async (req, res) => {
    try {
        let { phone, otp, password } = req.body; // Extract phone number, OTP, and new password from request body

        // Find the user by phone number in the database
        let isUserExists = await User.findOne({ phone: phone });

        // If user exists with the provided phone number
        if (isUserExists) {
            let code = isUserExists.code; // Get the stored OTP for the user
            // If the provided OTP matches the stored OTP
            if (code == otp) {
                let newPassword = await hashPassword(password); // Hash the new password

                // Define filter to find the user by phone number and update operation to set the new password
                const filter = { phone: phone };
                const update = {
                    $set: {
                        password: newPassword
                    },
                };

                // Update user's password in the database
                const check = await User.updateOne(filter, update);

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
                        msg: "Your Password Could Not Be Reset",
                    });
                }
            } else {
                // If OTP is invalid, return error response
                return res.status(200).send({
                    status: false,
                    msg: "Invalid OTP",
                });
            }
        } else {
            // If user does not exist with the provided phone number, return error response
            return res.status(200).send({
                status: false,
                msg: "Phone number does not exist"
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

// Function to get user profile
exports.getUserProfileFn = async (req, res) => {
    try {
        let userId = req.decoded.userId; // Get the user ID from the decoded JWT token

        // Find the user by ID in the database
        let isUserExists = await User.findOne({ _id: userId });

        // If user exists and is not null, return user profile
        if (isUserExists && isUserExists !== null) {
            return res.status(200).send({
                status: true,
                msg: "User Found Successfully",
                data: isUserExists // Send user profile data
            });
        } else {
            // If user does not exist with the provided ID, return error response
            return res.status(200).send({
                status: false,
                msg: "User Not Found",
                data: [] // Send empty data
            });
        }
    } catch (error) {
        // If an error occurs while getting user profile, return a server error response
        return res.status(400).send({
            status: false,
            msg: "Something went wrong"
        });
    }
}





