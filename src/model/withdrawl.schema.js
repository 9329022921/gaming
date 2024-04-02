const mongoose = require('mongoose');
const { Schema } = mongoose;

const withdrawlSchema = new Schema({
  userId: { type: String,require: true },
  password: { type: String,require: true },
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now },
});
module.exports = mongoose.model('withdrawl', withdrawlSchema)