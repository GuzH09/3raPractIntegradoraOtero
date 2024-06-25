export default class CurrentUserDTO {
  constructor (userdata) {
    this.first_name = userdata.first_name
    this.last_name = userdata.last_name
    this.age = userdata.age
    this.email = userdata.email
    this.role = userdata.role
    this.cart = userdata.cart
  }
}
