const mongoose = require('mongoose');

const subAdminSchema = new mongoose.Schema({
  name: { type: String },
  phone: { type: Number },
  email: { type: String },
  password: { type: String },
  address: { type: String },
  isDeleted: { type: Boolean, default: 0 },
  role: { type: String },
  permissions: {
    createUser: { type: Boolean, default: 0 }, // Boolean value indicating access
    viewUser: { type: Boolean, default: 0 } // Boolean value indicating access
  },
  code: { type: Number },
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now },
});
module.exports = mongoose.model('subAdminSchema', subAdminSchema);
