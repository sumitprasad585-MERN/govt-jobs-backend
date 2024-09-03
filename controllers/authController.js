const catchAsync = require('../utils/catchAsync');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const User = require('../models/userModel');
const AppError = require('../utils/AppError');
const sendMail = require('../utils/mail');

const signup = catchAsync(async (req, res, next) => {
  
  /** Get only required fields from the request body */
  const { name, username, email, password, confirmPassword } = req.body;

  /** Save the user, password will be hashed through pre save hook */
  const user = await User.create({
    name,
    username,
    email,
    password,
    confirmPassword,
  });

  /** Sign the token */
  const token = jwt.sign({ id: user.id }, process.env.JWT_SECRET, {
    expiresIn: process.env.JWT_EXPIRES_IN
  });

  /** Send the token */
  user.password = undefined;
  res.status(200).json({
    status: 'success',
    token,
    data: {
      user
    }
  });
});

const login = catchAsync(async (req, res, next) => {
  const user = await User.findOne({ $or: [{username: req.body.username}, {email: req.body.email}]}).select('+password');
  
  let isCorrect = false;
  if (user && req.body.password) {
    isCorrect = await user.verifyPassword(req.body.password, user.password);
  }

  if (!user || !isCorrect) {
    const appError = new AppError(400, 'Invalid credentials');
    return next(appError);
  }

  /** Sign the token */
  const token = jwt.sign({ id: user.id }, process.env.JWT_SECRET, {
    expiresIn: process.env.JWT_EXPIRES_IN
  });

  /** Send the token */
  res.status(200).json({
    status: 'success',
    token
  });
});

const protect = catchAsync(async (req, res, next) => {

  /** Check if auth token is passed with the request */
  let token;
  if (req.headers && req.headers.authorization) {
    token = req.headers.authorization.split(' ')[1];
  }

  if (!token) {
    return next(new AppError(401, 'You are not logged in, Please login'));
  }

  /** Verify token */
  const decoded = jwt.verify(token, process.env.JWT_SECRET);

  /** Check if the user still exits in db */
  const user = await User.findById(decoded.id);
  if (!user) {
    return next(new AppError(401, 'User deleted'));
  }

  /** Check if password was changed */
  let passwordWasChanged = user.didPasswordChange(decoded.iat);
  if (passwordWasChanged) {
    return next(new AppError(401, 'Password was changed'));
  }

  /** Grant access to the secured route */
  req.user = user;
  next();
});

const forgotPassword = catchAsync(async (req, res, next) => {

  /** Find the user based on username or email */
  let user;
  if (req.body.username || req.body.email) {
    user = await User.findOne({ $or: [{username: req.body.username}, {email: req.body.email}]});
  }

  if (!user) {
    return next(new AppError(404, 'User not found'));
  }

  /** Create password reset token and save hashed token to db */
  const resetToken = user.createPasswordResetToken();
  await user.save({ validateBeforeSave: false });

  /** Send the unhashed reset token to user on mail */
  const mailOptions = {
    to: user.email,
    subject: 'Password Reset URL | Valid for 1 Hour ⏰',
    text: `Please send a PATCH request to ${req.get('host')}/api/v1/users/resetPassword/${resetToken} Valid for 1 Hour. Please ignore if not invoked by you`
  };

  try {
    await sendMail(mailOptions);
  } catch (err) {
    user.passwordResetToken = undefined;
    user.passwordResetTokenExpiresAt = undefined;
    await user.save({ validateBeforeSave: false });
  }

  res.status(200).json({
    status: 'success',
    message: 'Reset URL sent to the user on mail'
  });
});

const resetPassword = catchAsync(async (req, res, next) => {

  /** Get the user based on reset token  and check validity of reset token*/
  const resetToken = req.params.resetToken;
  const hashedToken = crypto.createHash('sha256').update(resetToken).digest('hex');

  const user = await User.findOne({ passwordResetToken: hashedToken, passwordResetTokenExpiresAt: {$gt: Date.now()} });

  if (!user) {
    return next(new AppError(404, 'Invalid password reset token'));
  }

  /** Save the new password to db and invalidate reset token and its expiry */
  user.password = req.body.password;
  user.confirmPassword = req.body.confirmPassword;
  user.passwordResetToken = undefined;
  user.passwordResetTokenExpiresAt = undefined;
  await user.save({ validateBeforeSave: true });

  /** Sign the new access token */
  const token = jwt.sign({ id: user.id }, process.env.JWT_SECRET, {
    expiresIn: process.env.JWT_EXPIRES_IN
  });

  /** Send the token */
  res.status(200).json({
    status: 'success',
    token
  });
});

const updatePassword = catchAsync(async (req, res, next) => {

  /** User is already authenticated */
  const user = await User.findById(req.user.id).select('+password');

  if (!req.body.currentPassword || !req.body.newPassword || !req.body.confirmNewPassword) {
    return next(new AppError(400, 'Please enter currentPassword, newPassword, and confirmNewPassword'));
  }

  /** Validate user's current password */
  const isCorrect = await user.verifyPassword(req.body.currentPassword, user.password);
  if (!isCorrect) {
    return next(new AppError(400, 'Current password is incorrect'));
  }

  /** Save the new password to db */
  user.password = req.body.newPassword;
  user.confirmPassword = req.body.confirmNewPassword;
  await user.save({ validateBeforeSave: true });

  /** Sign the token */
  const token = jwt.sign({ id: user.id }, process.env.JWT_SECRET, {
    expiresIn: process.env.JWT_EXPIRES_IN
  });

  /** Send the token */
  res.status(200).json({
    status: 'success',
    message: 'Password updated successfully',
    token
  });
});

const restrictTo = (...roles) => {
  return (req, res, next) => {
    if (!roles.includes(req.user.role)) {
      return next(new AppError(403, 'You are not authorized to perform this action'));
    }

    next();
  }
}

module.exports = {
  signup,
  login,
  protect,
  forgotPassword,
  resetPassword,
  updatePassword,
  restrictTo
};
