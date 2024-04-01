// Import required modules
const db = require('../config/db'); // Import database configuration
const Admin = db.Admin; // Import the Admin model from the database
const { hashPassword, comparePassword, generateRandomNumber } = require('../helper/middleware'); // Import middleware functions for password hashing, comparison, and random number generation
const jwt = require('jsonwebtoken'); // Import JSON Web Token module for authentication
const secretKey = process.env.JWT_SECRET_KEY; // Get secret key from environment variables for JWT signing
const CryptoJS = require('crypto-js'); // Import CryptoJS module for cryptographic functions
const sendMail = require('../helper/email'); // Import function for sending emails
const bcrypt = require('bcryptjs'); // Import bcryptjs module for password hashing and comparison
const SubAdmin = db.SubAdmin;

// Function to register a new user
// exports.adminRegister = async (req, res) => {
//     // try {
//         // Extract user details from request body
//         let { name, number, password, role } = req.body;

//         // // Check if the user already exists in the database
//         // let isUserExists = await User.findOne({ email: email });
//         // if (isUserExists) {
//         //     // If user exists, return an error response
//         //     return res.status(200).send({
//         //         status: false,
//         //         msg: Msg.emailExists,
//         //     });
//         // } else {
//         // Hash the password using bcrypt
//         let newPassword = await hashPassword(password);

//         // // Generate a random number for verification code
//         // const randomNumber = await generateRandomNumber(10000, 20000);

//         // Create an object to store user data
//         let obj = {
//             name: name,
//             phone: number,
//             role: role,
//             password: newPassword,
//         };

//         // Insert the user data into the database
//         let data = await Admin.insertMany(obj);

//         // If data insertion is successful, send a verification email
//         if (data) {
//             // let emailSendFunction = await sendMail.mail(email, randomNumber);
//             return res.status(200).send({
//                 status: true,
//                 msg: Msg.registerSuccess,
//                 data: data[0]
//             });
//         } else {
//             // If data insertion fails, return an error response
//             return res.status(200).send({
//                 status: false,
//                 msg: Msg.registerError
//             });
//         }
//         // }
//     // } catch (error) {
//     //     // If an error occurs during registration process, return a server error response
//     //     return res.status(400).send({
//     //         status: false,
//     //         msg: Msg.err
//     //     });
//     // }
// }

  



// // Function to handle admin login


// Function to handle admin login
exports.adminLogin = async (req, res) => {
    try {
        let { phone, password } = req.body; // Destructure phone and password from request body
        let isAdminExists = await Admin.findOne({ phone: phone }); // Check if admin exists with the provided phone number
        if (isAdminExists && isAdminExists !== null) { // If admin exists
            let pass = isAdminExists.password; // Get hashed password from database
            let role = isAdminExists.role;
            let checkPassword = await bcrypt.compare(password, pass); // Compare provided password with hashed password
            if (checkPassword) { // If passwords match
                const payload = {
                    adminNumber: isAdminExists.phone,
                    role: role
                }; // Create payload for JWT token
                const token = jwt.sign(payload, secretKey, { expiresIn: '1h' }); // Generate JWT token with expiration time of 1 hour
                return res.status(200).send({ // Send success response with token
                    status: true,
                    msg: `${role} login successfully`,
                    token: token
                });
            } else { // If passwords don't match
                return res.status(200).send({ // Send failure response for invalid password
                    status: false,
                    msg: "Invalid password",
                });
            }
        } else { // If admin doesn't exist with provided phone number
            return res.status(200).send({ // Send failure response for invalid phone number
                status: false,
                msg: "Invalid number",
            });
        }
    } catch (error) { // Catch any errors that occur during execution
        return res.status(400).send({ // Send error response for internal server error
            status: false,
            msg: "Something went wrong"
        });
    }
};


// Function to handle creation of sub-admin
exports.createSubAdminFn = async (req, res) => {
    try {
        let Role = req.decoded.role; // Get the role from decoded JWT token
        let { phone, password, role, permission } = req.body; // Destructure phone, password, role, and permission from request body
        if (Role == "admin") { // If the role is admin
            let isExists = await SubAdmin.findOne({ phone: phone }); // Check if sub-admin already exists with the provided phone number
            if (isExists && isExists.role == 'subAdmin') { // If sub-admin already exists
                // Return an error response
                return res.status(200).send({
                    status: false,
                    msg: 'subAdmin already registered',
                });
            } else {
                // Hash the password using bcrypt
                let newPassword = await hashPassword(password);
                // Create an object to store sub-admin data
                let obj = {
                    name: "",
                    email: "",
                    address: "",
                    code: 0,
                    phone: phone,
                    password: newPassword,
                    role: role,
                };

                // Insert the sub-admin data into the database
                let data = await SubAdmin.insertMany(obj);
                if (data) { // If data insertion is successful
                    if (permission && permission !== null) { // If permission object is provided
                        let createUser = permission.createUser;
                        let viewUser = permission.viewUser;
                        // Define filter to find the sub-admin by phone number and update operation to set the new permissions
                        const filter = { phone: phone };
                        const update = {
                            $set:
                            {
                                'permissions.createUser': createUser,
                                'permissions.viewUser': viewUser
                            }
                        }; // Set both 'createUser' and 'viewUser' permissions

                        // Update sub-admin's permissions in the database
                        const check = await SubAdmin.updateOne(filter, update);
                        if (check) { // If permissions are updated successfully
                            return res.status(200).send({ // Send success response
                                status: true,
                                msg: 'subAdmin registered successfully',
                                data: `this is your id ${phone} and your password ${password}`
                            });
                        } else { // If permissions update fails
                            return res.status(200).send({ // Send failure response
                                status: false,
                                msg: 'subAdmin not registered',
                                data: data[0]
                            })
                        }
                    } else { // If permission object is not provided
                        return res.status(200).send({ // Send success response
                            status: true,
                            msg: 'subAdmin registered successfully',
                            data: `this is your id ${phone} and your password ${password}`
                        });
                    }
                } else { // If data insertion fails
                    return res.status(200).send({ // Send failure response
                        status: false,
                        msg: 'subAdmin not created'
                    });
                }
            }
        } else { // If the role is not admin
            return res.status(200).send({ // Send failure response
                status: true,
                msg: "Only admin can access",
            });
        }
    } catch (error) { // Catch any errors that occur during execution
        return res.status(400).send({ // Send error response for internal server error
            status: false,
            msg: "Something went wrong"
        });
    }
};
