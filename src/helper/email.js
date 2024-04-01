// Import nodemailer module
const nodemailer = require('nodemailer');

// Define a function named 'mail' to send an email with OTP
module.exports.mail = async function (email, otp) {
    // Create a transporter object with Gmail SMTP settings
    let transporter = nodemailer.createTransport({
        service: 'gmail', // Gmail service
        port: 465, // Port for secure SMTP (SSL)
        secure: true, // Enable secure connection
        logger: true, // Enable logging
        debug: true, // Enable debugging
        secureConnection: false, // Set secure connection to false
        auth: {
            user: 'shubhammandloi.ems@gmail.com', // Sender email address
            pass: 'guneotzyypycrtpj', // Sender email password (application-specific password)
        },
        tls: {
            rejectUnauthorized: true // Reject unauthorized TLS connections
        }
    });

    // Define email options
    let mailOptions = {
        from: "kpatel74155@gmail.com", // Sender email address
        to: email, // Receiver email address
        subject: 'This Mail Is Form e-commerce Project', // Email subject
        html: `This Is Your Otp ${otp} Please Don’t share your OTP, keep your account protected ` // Email content with OTP
    };

    // Send email using transporter
    transporter.sendMail(mailOptions, function (err, info) {
        if (err) { // If error occurs while sending email
            console.log("Error " + err); // Log the error
        } else { // If email sent successfully
            console.log("Email sent successfully", info.response); // Log the success message with email response info
        }
    });

}
