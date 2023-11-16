const { Schema, model } = require('mongoose');
const Joi = require('joi');

const { handleMongooseError } = require('../helper');

const emailRegexp = /^\w+([\.-]?\w+)*@\w+([\.-]?\w+)*(\.\w{2,3})+$/;

const registerSchema = Joi.object({
   nickName: Joi.string().required(),
   email: Joi.string().required(),
   password: Joi.string().min(5).required(),
});

const loginSchema = Joi.object({
   email: Joi.string().required(),
   password: Joi.string().min(5).required(),
});

const userSchema = new Schema({
   nickName: {
      type: String,
      required: [true, 'Set nickName'],
   },
   password: {
      type: String,
      minlenght: 5,
      required: [true, 'Set password for user'],
   },
   email: {
      type: String,
      required: [true, 'Email is required'],
      unique: true,
   },
   token: String,
});

const schemas = {
   registerSchema,
   loginSchema,
};

userSchema.post('save', handleMongooseError);

const User = model('user', userSchema);

module.exports = { User, schemas };
