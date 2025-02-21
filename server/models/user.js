const mongoose = require('mongoose');

const UserSchema = new mongoose.Schema({
  email: { type: String, unique: true, required: true },
  password: { type: String, required: true },
  name: { type: String, required: true },
  provider: String,
  role: { type: String, enum: ['user', 'admin', 'editor', 'viewer'], default: 'user' },
  emailVerified: { type: Boolean, default: false },
  emailVerificationToken: String,
});

const User = mongoose.model('User', UserSchema);

module.exports = { User };
