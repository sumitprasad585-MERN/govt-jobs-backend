const mongoose = require('mongoose');
const validator = require('validator');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');

const userSchema = new mongoose.Schema({
  name: {
    type: String,
    required: [true, 'user must have a name'],
    maxLength: [40, 'name must not exceed 40 characters']
  },
  username: {
    type: String,
    unique: true,
    sparse: true,
    minLength: [3, 'username should be atleast 3 character long']
  },
  email: {
    type: String,
    required: [true, 'email is required'],
    unique: [true],
    validate: [validator.isEmail, 'Please enter a valid email']
  },
  password: {
    type: String,
    required: [true, 'password is required'],
    minLength: [8, 'password must be 8 characters long'],
    select: false
  },
  confirmPassword: {
    type: String,
    required: [true, 'confirmPassowrd is required'],
    validate: {
      message: 'password and confirm password do not match',
      validator: function (val) {
        return this.password === val;
      }
    },
  },
  role: {
    type: String,
    enum: {
      values: ['admin', 'developer', 'moderator', 'user'],
      message: 'Invalid role'
    },
    default: 'user'
  },
  passwordResetToken: String,
  passwordResetTokenExpiresAt: Date,
  passwordChangedAt: Date,
  active: {
    type: Boolean,
    default: true,
  },
  createdAt: {
    type: Date,
    default: Date.now()
  }
});

/** Pre save hook to hash the password */
userSchema.pre('save', async function (next) {
  /** 'this' refers to document here */

  /** Do not rehash the password if user changes other fields */
  if (!this.isModified('password')) return next();

  this.password = await bcrypt.hash(this.password, 12);
  this.confirmPassword = undefined;

  next();
});

/** Instance schema method to verify the password */
userSchema.methods.verifyPassword = async function (userPassword, dbPassword) {
  /** 'this' refers to document here */

  let isCorrect = await bcrypt.compare(userPassword, dbPassword);
  return isCorrect;
};

/** Instance schema method to check if password was changed post issuing the token */
userSchema.methods.didPasswordChange = function (issuedJwtTimestamp) {
  /** 'this' refers to document here */
  if (this.passwordChangedAt) {
    const changeTimestamp = parseInt(this.passwordChangedAt.getTime() / 1000, 10);
    return changeTimestamp > issuedJwtTimestamp;
  }
  return false;
};

/** Instance schema method to create password reset token */
userSchema.methods.createPasswordResetToken = function () {
  /** 'this' refers to document here */
  const resetToken = crypto.randomBytes(32).toString('hex');
  const hashedToken = crypto.createHash('sha256').update(resetToken).digest('hex');
  const numHours = 1; // reset token expires after 1 hour
  this.passwordResetToken = hashedToken;
  this.passwordResetTokenExpiresAt = Date.now() + 1000 * 60 * 60 * numHours;
  return resetToken;
};

/** Query middleware to not return inactive users */
userSchema.pre(/^find/, function (next) {
  /** 'this' refers to query object here */
  this.find({ active: { $ne: false }});
  next();
});

/** Create index for username and email */
userSchema.index({ username: 1 }, { unique: true, sparse: true });
userSchema.index({ email: 1 }, { unique: true });

const User = mongoose.model('User', userSchema);

module.exports = User;
