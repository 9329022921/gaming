const express = require('express') // Importing the express module

// Creating an instance of Express router
var router = express.Router()

// Mounting the userRouter under the '/router' path prefix
router.use('/router', require('./userRouter'))

// Mounting the adminRouter under the '/router' path prefix
router.use('/router', require('./adminRouter'))

router.use('/router', require('./subAdminRouter'))
// Exporting the router instance to be used by other parts of the application
module.exports = router
