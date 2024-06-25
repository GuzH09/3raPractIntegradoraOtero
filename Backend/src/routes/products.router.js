import { Router } from 'express'
import passport from 'passport'

import ProductController from '../controllers/ProductController.js'
import { uploader } from '../utils/multerUtil.js'
import productModel from '../models/productModel.js'
import { roleauth } from '../middlewares/role-authorization.js'

const productsRouter = Router()
const PM = new ProductController()

// Get All Products - Get All Products With Page, Limit, Sort and Query
productsRouter.get('/', async (req, res) => {
  try {
    let { page = 1, limit = 10, sort } = req.query
    page = parseInt(page)
    limit = parseInt(limit)
    const options = {
      page,
      limit,
      lean: true
    }
    const sortOptions = {}
    if (sort === 'asc') {
      sortOptions.price = 1
    } else if (sort === 'desc') {
      sortOptions.price = -1
    }
    const queryOptions = {}
    if (req.query.category) {
      queryOptions.category = req.query.category
    } else if (req.query.stock) {
      queryOptions.stock = parseInt(req.query.stock)
    }
    options.sort = sortOptions
    const result = await productModel.paginate(queryOptions, options)
    const baseURL = 'http://localhost:8080/api/products'
    if (result.hasPrevPage) {
      let strURLprev = `${baseURL}?page=${result.prevPage}`
      for (const itemQueryKey in req.query) {
        if (itemQueryKey !== 'page') {
          strURLprev = strURLprev + '&' + itemQueryKey + '=' + req.query[itemQueryKey]
        }
      }
      result.prevLink = strURLprev
    } else {
      result.prevLink = ''
    }
    if (result.hasNextPage) {
      let strURLprev = `${baseURL}?page=${result.nextPage}`
      for (const itemQueryKey in req.query) {
        if (itemQueryKey !== 'page') {
          strURLprev = strURLprev + '&' + itemQueryKey + '=' + req.query[itemQueryKey]
        }
      }
      result.nextLink = strURLprev
    } else {
      result.nextLink = ''
    }
    result.isValid = !(page <= 0 || page > result.totalPages)
    const response = {
      status: 'success',
      payload: result.docs,
      totalPages: result.totalPages,
      prevPage: result.prevPage,
      nextPage: result.nextPage,
      page: result.page,
      hasPrevPage: result.hasPrevPage,
      hasNextPage: result.hasNextPage,
      prevLink: result.prevLink,
      nextLink: result.nextLink,
      isValid: result.isValid
    }
    req.logger.info({ message: 'All Products endpoint', status: response.status })
    res.status(200).send(response)
  } catch (error) {
    req.logger.warning({ error: error.message })
    res.status(500).send({ error: error.message })
  }
})

// Get Product By Id
productsRouter.get('/:pid', async (req, res) => {
  const productId = req.params.pid
  const products = await PM.getProductById(productId)
  if (products.error) {
    req.logger.warning({ products })
    res.status(400).send(products)
  } else {
    req.logger.info({ message: 'Get product by id', products })
    res.status(200).send({ ...products, _id: products._id.toString() })
  }
})

// Create New Product
productsRouter.post('/', passport.authenticate('jwt', { session: false }), roleauth(['premium', 'admin']), async (req, res, next) => {
  uploader.array('thumbnails')(req, res, (err) => {
    if (err) {
      req.logger.warning({ error: 'Error uploading image.' })
      return res.status(400).send({ error: 'Error uploading image.' })
    }
    next()
  })
}, async (req, res) => {
  let thumbnails = []

  // If there are files, get their paths
  if (req.files && req.files.length > 0) {
    thumbnails = req.files.map(file => file.path)
  }

  // Get Product Data from Body
  const { title, description, code, price, stock, category } = req.body

  // Status is true by default
  // Thumbnails is not required, [] by default
  const owner = (req.user.role === 'premium') ? req.user.email : 'admin'
  const newObjectData = { title, description, code, price, stock, category, thumbnails, owner }
  try {
    const result = await PM.addProduct(newObjectData)
    if (result.error) {
      req.logger.warning({ result })
      res.status(400).send(result)
    } else {
      req.logger.info({ message: 'Create New Product Endpoint', result })
      res.status(201).send(result)
    }
  } catch (e) {
    req.logger.warning({ error: e.message })
    res.status(400).send({ error: e.message })
  }
})

// Update Existing Product
productsRouter.put('/:pid', passport.authenticate('jwt', { session: false }), roleauth(['premium', 'admin']), async (req, res) => {
  const { title, description, code, price, stock, category, thumbnails } = req.body
  const productId = req.params.pid
  const owner = (req.user.role === 'premium') ? req.user.email : 'admin'
  const newObjectData = { title, description, code, price, stock, category, thumbnails, owner }
  const result = await PM.updateProduct(productId, newObjectData, owner)
  if (result.success) {
    req.logger.info({ message: 'Update Existing Product Endpoint', result })
    res.status(201).send(result)
  } else {
    req.logger.warning({ result })
    res.status(400).send(result)
  }
})

// Delete Existing Product
productsRouter.delete('/:pid', passport.authenticate('jwt', { session: false }), roleauth(['premium', 'admin']), async (req, res) => {
  // Get Product Id from Params
  const productId = req.params.pid
  const owner = (req.user.role === 'premium') ? req.user.email : 'admin'
  const result = await PM.deleteProduct(productId, owner)
  if (result.success) {
    req.logger.info({ message: 'Delete Existing Product Endpoint', result })
    res.status(201).send(result)
  } else {
    req.logger.warning({ result })
    res.status(400).send(result)
  }
})

export default productsRouter
