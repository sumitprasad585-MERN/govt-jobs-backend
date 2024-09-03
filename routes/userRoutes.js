const express = require('express');
const { signup, login, protect, forgotPassword, resetPassword, updatePassword, restrictTo } = require('../controllers/authController');
const { getAllUsers, getUser, updateUser, deleteUser, updateMe, deleteMe } = require('../controllers/userController');

const router = express.Router();

router.post('/signup', signup);

router.post('/login', login);

router.post('/forgotPassword', forgotPassword);

router.patch('/resetPassword/:resetToken', resetPassword);

router.patch('/updatePassword', protect, updatePassword);

router.get('/', protect, restrictTo('admin', 'developer', 'moderator'), getAllUsers);

router.get('/:id', protect, restrictTo('admin', 'developer', 'moderator'), getUser);

router.patch('/updateMe', protect, updateMe);

router.patch('/:id', protect, restrictTo('admin', 'developer', 'moderator'), updateUser);

router.delete('/deleteMe', protect, deleteMe);

router.delete('/:id', protect, restrictTo('admin'), deleteUser);

module.exports = router;
