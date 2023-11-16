const bcryp = require('bcrypt');
const jwt = require('jsonwebtoken');
const { nanoid } = require('nanoid');

const { User } = require('../models/user');

const { HttpError, ctrlWrapper } = require('../helper');

const { SEKRET_KEY, BASE_URL } = process.env;

const register = async (req, res) => {
   const { email, password } = req.body;
   const user = await User.findOne({ email });
   if (user) {
      throw HttpError(409, 'Email already exist');
   }
   const hashPassword = await bcryp.hash(password, 10);
   const token = jwt.sign(payload, SEKRET_KEY, { expiresIn: '23h' });
   const newUser = await User.create({
      ...req.body,
      password: hashPassword,
      token,
   });
   res.status(201).json({
      nickName: newUser.nickName,
      email: newUser.email,
      token,
   });
};

const login = async (req, res) => {
   const { email, password } = req.body;
   const user = await User.findOne({ email });
   if (!user) {
      throw HttpError(401, 'Email or password is incorrect');
   }
   const passwordCompare = await bcryp.compare(password, user.password);
   if (!passwordCompare) {
      throw HttpError(401, 'Email or password is incorrect');
   }
   const payload = {
      id: user._id,
   };
   const token = jwt.sign(payload, SEKRET_KEY, { expiresIn: '23h' });
   await User.findByIdAndUpdate(user._id, { token });

   res.json({
      token,
   });
};

const logout = async (req, res) => {
   const { _id } = req.user;
   await User.findByIdAndUpdate(_id, { token: '' });
   res.status(204).json({
      message: 'No Content',
   });
};

const getCurrent = async (req, res) => {
   const { email, nickName } = req.user;
   res.json({ email, nickName });
};

module.exports = {
   register: ctrlWrapper(register),
   login: ctrlWrapper(login),
   logout: ctrlWrapper(logout),
   getCurrent: ctrlWrapper(getCurrent),
};
