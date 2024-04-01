var express = require('express')
var app = express()
const controller=require('../controller/index')
const { validateUser,validateLogin, handleValidationErrors } =require('../helper/vallidation')
const {authenticateToken} =require('../helper/middleware')

// app.post('/registerr',controller.adminController.adminRegister)
app.post('/adminLogin',validateLogin,handleValidationErrors,controller.adminController.adminLogin)
app.post('/createSubAdmin',authenticateToken,controller.adminController.createSubAdminFn)


module.exports=app