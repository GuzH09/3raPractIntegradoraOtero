import mongoose from 'mongoose'
import { createHash } from '../utils/functionsUtil.js'

const userCollection = 'users'

const userSchema = mongoose.Schema({
  first_name: {
    type: String,
    minLength: 3,
    require: true
  },
  last_name: {
    type: String,
    minLength: 3,
    require: true
  },
  email: {
    type: String,
    minLength: 5,
    require: true,
    unique: true
  },
  age: {
    type: Number,
    min: 18,
    require: true
  },
  password: {
    type: String,
    hash: true,
    minLength: 5,
    require: true
  },
  cart: {
    type: [{
      type: mongoose.Schema.Types.ObjectId,
      ref: 'carts'
    }],
    default: []
  },
  role: {
    type: String,
    require: true,
    default: 'user'
  }
})

userSchema.pre('save', function () {
  this.password = createHash(this.password)
})

const userModel = mongoose.model(userCollection, userSchema)

export default userModel
