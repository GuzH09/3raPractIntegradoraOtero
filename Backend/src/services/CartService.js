import cartModel from '../models/CartModel.js'

export default class CartService {
  // Patron de diseño DAO
  async getCarts () {
    try {
      const carts = await cartModel.find().lean()
      const cartsWithStrIds = carts.map(cart => {
        return {
          ...cart,
          _id: cart._id.toString()
        }
      })
      return cartsWithStrIds
    } catch (error) {
      return { error: error.message }
    }
  }

  async getCartById (id) {
    const cart = await cartModel.findOne({ _id: id }).populate('products.product').lean()
    if (cart) {
      return cart
    } else {
      return { error: "That cart doesn't exists." }
    }
  }

  async addCart () {
    try {
      await cartModel.create({})
      return { success: 'Cart added.' }
    } catch (error) {
      return { error: error.message }
    }
  }

  async AddProductToCart (cartId, productId) {
    try {
      const cart = await this.getCartById(cartId)

      if (cart.error) {
        return { error: cart.error }
      }

      // Check if the product already exists in the cart
      const productIndex = cart.products.findIndex(item => item.product._id.toString() === productId)

      if (productIndex === -1) {
        // If the product doesn't exist, add it with quantity 1
        cart.products.push({ product: productId, quantity: 1 })
        await cartModel.updateOne({ _id: cartId }, { products: cart.products })
        return { success: `Product ${productId} added on cart ${cartId}.` }
      } else {
        // If it already exists, quantity should go up by 1
        cart.products[productIndex].quantity++
        await cartModel.updateOne({ _id: cartId }, { products: cart.products })
        return { success: `Added on more product ${productId} on cart ${cartId}.` }
      }
    } catch (error) {
      return { error: error.message }
    }
  }

  async updateProductQuantityFromCart (cartId, productId, quantity) {
    try {
      // Update the quantity of the specified product in the cart
      const result = await cartModel.findByIdAndUpdate(
        cartId,
        { $set: { 'products.$[elem].quantity': quantity } },
        { arrayFilters: [{ 'elem.product': productId }] }
      )

      // If cart doesn't exist, return an error
      if (!result) {
        return { error: `Cart with id ${cartId} doesn't exist.` }
      }

      // If the product was not found in the cart, return an error
      if (!result.products || result.products.length === 0) {
        return { error: `Product ${productId} not found in cart ${cartId}.` }
      }

      return { success: `Product ${productId} quantity in cart ${cartId} updated.` }
    } catch (error) {
      return { error: error.message }
    }
  }

  async updateProductsFromCart (cartId, products) {
    try {
      const result = await cartModel.findByIdAndUpdate({ _id: cartId }, { products })
      // If cart doesn't exist, return an error
      if (!result) {
        return { error: `Cart with id ${cartId} doesn't exists.` }
      }
      return { success: `Cart with id ${cartId} updated.` }
    } catch (error) {
      return { error: error.message }
    }
  }

  async emptyCartById (id) {
    try {
      const result = await cartModel.findByIdAndUpdate({ _id: id }, { products: [] })
      // If cart doesn't exist, return an error
      if (!result) {
        return { error: `Cart with id ${id} doesn't exists.` }
      }
      return { success: 'Cart emptied.' }
    } catch (error) {
      return { error: error.message }
    }
  }

  async deleteProductFromCart (cartId, productId) {
    try {
      const result = await cartModel.findByIdAndUpdate(
        cartId,
        { $pull: { products: { product: productId } } }
      )
      // If cart doesn't exist, return an error
      if (!result) {
        return { error: `Cart with id ${cartId} doesn't exists.` }
      }

      return { success: `Product ${productId} has been deleted from ${cartId}.` }
    } catch (error) {
      return { error: error.message }
    }
  }
}
