import CartService from '../services/CartService.js'

export default class CartController {
// Patron de diseño Repository
  constructor () {
    this.cartService = new CartService()
  }

  async getCarts () {
    return this.cartService.getCarts()
  }

  async getCartById (cid) {
    return this.cartService.getCartById(cid)
  }

  async addCart () {
    return this.cartService.addCart()
  }

  async AddProductToCart (cid, pid) {
    return this.cartService.AddProductToCart(cid, pid)
  }

  async updateProductQuantityFromCart (cid, pid, quantity) {
    return this.cartService.updateProductQuantityFromCart(cid, pid, quantity)
  }

  async updateProductsFromCart (cid, products) {
    return this.cartService.updateProductsFromCart(cid, products)
  }

  async emptyCartById (cid) {
    return this.cartService.emptyCartById(cid)
  }

  async deleteProductFromCart (cid, pid) {
    return this.cartService.deleteProductFromCart(cid, pid)
  }
}
