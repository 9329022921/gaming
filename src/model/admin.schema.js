const mongoose = require('mongoose');
const { Schema } = mongoose;

const adminSchema = new Schema({
  name: { type: String },
  phone: { type: Number},
  role: { type: String },
  password: { type: String },
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now },
});
module.exports = mongoose.model('admin', adminSchema)