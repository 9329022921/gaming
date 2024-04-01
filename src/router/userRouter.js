var express = require('express')
var app = express()
const controller=require('../controller/index')
const { validateUser,validateLogin, handleValidationErrors } =require('../helper/vallidation')
const {authenticateToken} =require('../helper/middleware')



app.post('/getOtp',controller.userController.getOtp)
app.post('/userSighUp',controller.userController.otpVerifyfn)
app.post('/resendOtp',controller.userController.resendOtpfn)
app.post('/userlogin',controller.userController.userLogin)

app.post('/changePassword',authenticateToken,controller.userController.changePassword)
app.post('/forgetPasswordSendOtp',controller.userController.forgetPasswordSendOtpFn)
app.post('/forgetPasswordFn',controller.userController.forgetPasswordFn)

app.get('/getUserProfile',authenticateToken,controller.userController.getUserProfileFn)






module.exports=app