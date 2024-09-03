const catchAsync = require("../utils/catchAsync");
const User = require('../models/userModel');
const AppError = require("../utils/AppError");
const jwt = require('jsonwebtoken');

const getAllUsers = catchAsync(async (req, res, next) => {
  const users = await User.find({});
  res.status(200).json({
    status: 'success',
    length: users.length,
    data: {
      users
    }
  });
});

const getUser = catchAsync(async (req, res, next) => {
  const user = await User.findById(req.params.id);
  if (!user) {
    return res.status(404).json({
      status: 'fail',
      message: 'User not found'
    });
  }
  res.status(200).json({
    status: 'success',
    data: {
      user
    }
  });
});

const createSafeObj = (requestBody) => {
  const allowedModifications = ['username', 'name'];
  const safeObj = {};
  Object.keys(requestBody).forEach(current => {
    if (allowedModifications.includes(current)) {
      safeObj[current] = requestBody[current];
    }
  });

  return safeObj;
};

/** route for user to update self details */
const updateMe = catchAsync(async (req, res, next) => {

  /** User is already authenticated */
  const { currentPassword, newPassword, confirmNewPassword } = req.body;
  if (currentPassword || newPassword || confirmNewPassword) {
    return next(new AppError(400, 'This route is responsible for updating details. Please use update password functionality to update password'));
  }

  const safeObj = createSafeObj(req.body);

  const updatedUser = await User.findByIdAndUpdate(req.user.id, safeObj, {
    new: true,
    runValidators: true
  });

  /** Sign a new token post details are updated */
  const token = jwt.sign({ id: updateUser.id }, process.env.JWT_SECRET, {
    expiresIn: process.env.JWT_EXPIRES_IN
  });

  /** Send the token */
  res.status(200).json({
    status: 'success',
    token,
    data: {
      user: updatedUser
    }
  });
});

/** route for admins to update any user using id */
const updateUser = catchAsync(async (req, res, next) => {
  const updatedUser = await User.findByIdAndUpdate(req.params.id, req.body, {
    runValidators: true,
    new: true
  });
  res.status(200).json({
    status: 'success',
    data: {
      user: updatedUser
    }
  });
});

/** route for user to delete himself (only makes the user inactive as admins would have deletion rights) */
const deleteMe = catchAsync(async (req, res, next) => {

  /** User is already authenticated */
  const user = req.user;
  user.active = false;
  await user.save({ validateBeforeSave: false });
  
  res.status(204).json({
    status: 'success',
    data: null
  });
});

/** route for admins to delete any user from db */
const deleteUser = catchAsync(async (req, res, next) => {
  await User.findByIdAndDelete(req.params.id);
  res.status(204).json({
    status: 'success',
    data: null
  });
});

module.exports = {
  getAllUsers,
  getUser,
  updateMe,
  updateUser,
  deleteMe,
  deleteUser
};
