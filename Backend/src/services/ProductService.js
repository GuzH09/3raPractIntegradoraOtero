import productModel from '../models/productModel.js'

export default class ProductService {
  // Patron de diseño DAO
  async getProducts () {
    try {
      const products = await productModel.find().lean()
      const productsWithStrIds = products.map(product => {
        return {
          ...product,
          _id: product._id.toString()
        }
      })
      return productsWithStrIds
    } catch (error) {
      return { error: error.message }
    }
  }

  async getProductById (id) {
    try {
      const product = await productModel.findOne({ _id: id }).lean()
      return product
    } catch (error) {
      return { error: error.message }
    }
  }

  async addProduct (validatedData) {
    try {
      const fileProducts = await this.getProducts()

      if (fileProducts.some(product => product.code === validatedData.code)) {
        return { error: `Error: code ${validatedData.code} already exists.` }
      }

      const { title, description, code, price, stock, category, thumbnails, owner } = validatedData

      await productModel.create({ title, description, code, price, stock, category, owner, thumbnails: thumbnails ?? [] })
      return { success: 'Product added.' }
    } catch (error) {
      return { error: error.message }
    }
  }

  async updateProduct (id, productData, owner) {
    try {
      const product = await this.getProductById(id)
      if (product.error) return { product }
      if (product === null) return { error: `Product with id ${id} not found.` }
      if (owner !== 'admin' && product.owner !== owner) return { error: 'You are not the owner of this product.' }

      await productModel.updateOne({ _id: id }, productData)
      return { success: 'Product updated.' }
    } catch (error) {
      return { error: error.message }
    }
  }

  async deleteProduct (id, owner) {
    try {
      const product = await this.getProductById(id)
      if (product.error) return { product }
      if (product === null) return { error: `Product with id ${id} not found.` }
      if (owner !== 'admin' && product.owner !== owner) return { error: 'You are not the owner of this product.' }

      const result = await productModel.deleteOne({ _id: id })
      if (result.deletedCount === 0) return { error: `Product with id ${id} not found.` }
      return { success: 'Product deleted.' }
    } catch (error) {
      return { error: error.message }
    }
  }
}
