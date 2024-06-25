import UserService from '../services/UserService.js'

export default class UserController {
// Patron de diseño Repository
  constructor () {
    this.userService = new UserService()
  }

  async getAllUsers () {
    return this.userService.getAllUsers()
  }

  async getUser (uid) {
    return this.userService.getUser(uid)
  }

  async getUserByEmail (useremail) {
    return this.userService.getUserByEmail(useremail)
  }

  async registerUser (user) {
    const { first_name, last_name, email, age, password } = user

    if (!first_name || !last_name || !email || !age || !password) {
      return { error: 'Error registering user.' }
    }

    return this.userService.registerUser(user)
  }

  async loginUser (email, password) {
    if (!email || !password) {
      return { error: 'Error login user.' }
    }

    return this.userService.loginUser(email, password)
  }

  async updateUser (uid, role) {
    return this.userService.updateUser(uid, role)
  }

  async resetPassword (uid, password) {
    return this.userService.resetPassword(uid, password)
  }
}
