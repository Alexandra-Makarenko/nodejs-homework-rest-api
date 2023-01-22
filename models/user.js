const {Schema, model} = require("mongoose");
const Joi = require("joi")

const {handleMongooseError} = require("../helpers")

const emailRegexp = /^(([^<>()\[\]\\.,;:\s@"]+(\.[^<>()\[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/

const userSchema = new Schema({
  password: {
    type: String,
    required: [true, 'Password is required'],
  },
  email: {
    type: String,
    required: [true, 'Email is required'],
    unique: true,
  },
  subscription: {
    type: String,
    enum: ["starter", "pro", "business"],
    default: "starter"
  },
  token: {
    type: String,
    default: null,
  },
  avatarURL: String,
  verify: {
    type: Boolean,
    default: false,
  },
  verificationToken: {
    type: String
  },
}, {versionKey: false, timestamps: true})

userSchema.post("save", handleMongooseError)

const registerSchema = Joi.object({
    email: Joi.string().pattern(emailRegexp).required(),
    password: Joi.string().min(6).required(),
})

const loginSchema = Joi.object({
    email: Joi.string().pattern(emailRegexp).required(),
    password: Joi.string().min(6).required(),
})

const verifySchema = Joi.object({
    email: Joi.string().pattern(emailRegexp).required(),
})

const schemas = {
    registerSchema,
    loginSchema,
    verifySchema
}

const User = model("user", userSchema);

module.exports = {
    User,
    schemas,
}