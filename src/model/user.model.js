const mongoose = require('mongoose')

const userSchema = new mongoose.Schema({
    name: { type: String },
    phone: { type: Number },
    password: { type: String },
    code: { type: Number },
    isVerified: { type: Boolean, default: false },
    createdAt: { type: Date, default: Date.now },
    updatedAt: { type: Date, default: Date.now },
})
module.exports = mongoose.model('userSchema', userSchema)
