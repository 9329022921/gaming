var express = require('express')
var app = express()
const controller=require('../controller/index')
const { validateUser,validateLogin, handleValidationErrors } =require('../helper/vallidation')
const {authenticateToken} =require('../helper/middleware')



// app.post('/register',validateUser,handleValidationErrors,controller.userController.userRegister)
app.post('/login',validateLogin,handleValidationErrors,controller.subAdminController.subAdminLogin)
app.post('/otpVerify',controller.subAdminController.otpVerifyfn)
app.post('/resendOtp',controller.subAdminController.resendOtpfn)

app.post('/changePassword',authenticateToken,controller.subAdminController.changePassword)
app.post('/forgetPasswordSendOtp',controller.subAdminController.forgetPasswordSendOtpFn)
app.post('/forgetPasswordFn',controller.subAdminController.forgetPasswordFn)






module.exports=app