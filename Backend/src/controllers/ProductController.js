import ProductService from '../services/ProductService.js'

export default class ProductController {
// Patron de diseño Repository
  constructor () {
    this.productService = new ProductService()
  }

  async getProducts () {
    return this.productService.getProducts()
  }

  async getProductById (pid) {
    return this.productService.getProductById(pid)
  }

  async addProduct (productObj, owner) {
    const validatedData = this.#validateNewProduct(productObj)
    return this.productService.addProduct(validatedData, owner)
  }

  async updateProduct (id, productData, owner) {
    this.#validateUpdateProduct(productData)
    return this.productService.updateProduct(id, productData, owner)
  }

  async deleteProduct (pid, owner) {
    return this.productService.deleteProduct(pid, owner)
  }

  #validateNewProduct (objectFields) {
    const newObjectData = {}

    const requiredFields = ['title', 'description', 'code', 'price', 'stock', 'category']

    // Validates fields
    for (const field in objectFields) {
      // If field is missing and field is required : Missing Field
      if (!objectFields[field] && requiredFields.includes(field)) {
        throw new Error(`Missing field: ${field} .`)
      }
      // If field is not missing add to new object
      if (objectFields[field]) {
        newObjectData[field] = objectFields[field]
      }

      switch (field) {
        case 'title':
        case 'description':
        case 'code':
        case 'category':
          if (typeof objectFields[field] !== 'string') {
            throw new Error(`Invalid type for field: ${field}. Expected: String.`)
          }
          break
        case 'price':
        case 'stock':
          // if ( typeof objectFields[field] !== 'number' ) {
          //     return { error: `Invalid type for field: ${field}. Expected: Number.` };
          // }
          break
        case 'thumbnails':
          // It only returns an error if the thumbnail HAS a value, but it is not an array.
          if (objectFields[field] && !Array.isArray(objectFields[field])) {
            throw new Error(`Invalid type for field: ${field}. Expected: array of strings.`)
          }
          break
        default:
          break
      }
    }

    return newObjectData
  }

  #validateUpdateProduct = (objectFields) => {
    const newObjectData = {}

    // Validates new Fields
    for (const field in objectFields) {
      // If field is not undefined, push the field into the new object
      if (objectFields[field]) {
        newObjectData[field] = objectFields[field]
      }

      switch (field) {
        case 'title':
        case 'description':
        case 'code':
        case 'category':
          // It only returns an error if the title-description-code-category HAS a value, but it is not a string.
          if (objectFields[field] && typeof objectFields[field] !== 'string') {
            throw new Error(`Invalid type for field: ${field}. Expected: String.`)
          }
          break
        case 'price':
        case 'stock':
          // It only returns an error if the stock or price HAS a value, but it is not a number.
          if (objectFields[field] && typeof objectFields[field] !== 'number') {
            throw new Error(`Invalid type for field: ${field}. Expected: Number.`)
          }
          break
        case 'thumbnails':
          // It only returns an error if the thumbnail HAS a value, but it is not an array.
          if (objectFields[field] && !Array.isArray(objectFields[field])) {
            throw new Error(`Invalid type for field: ${field}. Expected: array of strings.`)
          }
          break
        default:
          break
      }
    }

    return newObjectData
  }
}
