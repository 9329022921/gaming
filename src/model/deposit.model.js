const mongoose = require('mongoose');
const { Schema } = mongoose;

const depositSchema = new Schema({
  utrNumber: { type: Number,require: true },
  file:{type: String, require:true},
  amount: { type: Number, require:true},
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now },
});
module.exports = mongoose.model('deposit', depositSchema)