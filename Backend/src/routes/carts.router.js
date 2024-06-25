import { Router } from 'express'
import passport from 'passport'

import CartController from '../controllers/CartController.js'
import ProductController from '../controllers/ProductController.js'
import TicketController from '../controllers/TicketController.js'
import { roleauth } from '../middlewares/role-authorization.js'

const cartsRouter = Router()
const CM = new CartController()
const PM = new ProductController()
const TM = new TicketController()

// Create New Empty Cart
cartsRouter.post('/', passport.authenticate('jwt', { session: false }), roleauth(['admin']), async (req, res) => {
  const result = await CM.addCart()
  if (result.success) {
    req.logger.info({ message: 'Create New Empty Cart Endpoint', result })
    res.status(201).send(result)
  } else {
    req.logger.warning({ error: "Cart couldn't be created." })
    res.status(400).send({ error: "Cart couldn't be created." })
  }
})

// Get Cart By Id
cartsRouter.get('/:cid', passport.authenticate('jwt', { session: false }), async (req, res) => {
  const cartId = req.params.cid
  const carts = await CM.getCartById(cartId)
  if (carts.error) {
    req.logger.warning({ carts })
    res.status(400).send(carts)
  } else {
    req.logger.info({ message: 'Get Cart By Id Endpoint', carts })
    res.status(200).send({ carts })
  }
})

// Add Product to Cart
cartsRouter.post('/:cid/product/:pid', passport.authenticate('jwt', { session: false }), async (req, res) => {
  const cartId = req.params.cid
  const productId = req.params.pid
  const product = await PM.getProductById(productId)
  // Product Error
  if (product.error) {
    req.logger.warning({ product })
    return res.status(400).send(product)
  }
  // Product Not Found
  if (product === null) {
    req.logger.warning({ error: `Product with id ${productId} not found.` })
    return res.status(400).send({ error: `Product with id ${productId} not found.` })
  }
  // Check if the user is a premium user and the owner of the product
  if (req.user.role === 'premium' && product.owner === req.user.email) {
    req.logger.warning({ error: 'Premium users cannot add their own products to the cart.' })
    return res.status(400).send({ error: 'Premium users cannot add their own products to the cart.' })
  }

  req.logger.info({ message: 'Add Product to Cart Endpoint - Get Cart By Id', product })
  // Add Product to Cart Error
  const result = await CM.AddProductToCart(cartId, productId)
  if (result.success) {
    req.logger.info({ message: 'Add Product to Cart Endpoint', result })
    res.status(201).send(result)
  } else {
    req.logger.warning({ result })
    res.status(400).send({ result })
  }
})

// Delete All Products From Cart
cartsRouter.delete('/:cid', passport.authenticate('jwt', { session: false }), async (req, res) => {
  const cartId = req.params.cid
  const carts = await CM.emptyCartById(cartId)
  if (carts.error) {
    req.logger.warning({ carts })
    res.status(400).send(carts)
  } else {
    req.logger.info({ message: 'Delete All Products From Cart Endpoint', carts })
    res.status(200).send({ carts })
  }
})

// Delete Single Product From Cart
cartsRouter.post('/:cid/product/:pid/delete', passport.authenticate('jwt', { session: false }), async (req, res) => {
  const cartId = req.params.cid
  const productId = req.params.pid
  const carts = await CM.deleteProductFromCart(cartId, productId)
  if (carts.error) {
    req.logger.warning({ carts })
    res.status(400).send(carts)
  } else {
    req.logger.info({ message: 'Delete Single Product From Cart Endpoint', carts })
    res.status(200).send({ carts })
  }
})

// PUT Single Cart With Products Object
cartsRouter.put('/:cid', passport.authenticate('jwt', { session: false }), async (req, res) => {
  const { products } = req.body
  const cartId = req.params.cid
  // For loop, for every product id in products array
  for (const item of products) {
    const productId = item.product
    const product = await PM.getProductById(productId)
    if (product.error) {
      req.logger.warning({ product })
      res.status(400).send(product)
    } else {
      req.logger.info({ message: 'PUT Single Cart With Products Object', product })
    }
  } // If all products exist, we continue with the update
  const carts = await CM.updateProductsFromCart(cartId, products)
  if (carts.error) {
    req.logger.warning({ carts })
    res.status(400).send(carts)
  } else {
    req.logger.info({ message: 'PUT Single Cart With Products Object Endpoint', carts })
    res.status(200).send({ carts })
  }
})

// PUT Quantity of Product From Cart
cartsRouter.put('/:cid/product/:pid', passport.authenticate('jwt', { session: false }), async (req, res) => {
  const { quantity } = req.body
  const cartId = req.params.cid
  const productId = req.params.pid
  const carts = await CM.updateProductQuantityFromCart(cartId, productId, quantity)
  if (carts.error) {
    req.logger.warning({ carts })
    res.status(400).send(carts)
  } else {
    req.logger.info({ message: 'PUT Quantity of Product From Cart Endpoint', carts })
    res.status(200).send({ carts })
  }
})

// Finish purchase of cart
cartsRouter.post('/:cid/purchase', passport.authenticate('jwt', { session: false }), async (req, res) => {
  const cartId = req.params.cid
  const cart = await CM.getCartById(cartId)
  if (cart.error) {
    req.logger.warning({ cart })
    res.status(400).send(cart)
  } else {
    req.logger.info({ message: 'Get Cart By Id Endpoint', cart })
  }
  let number = 0

  for (const product of cart.products) {
    if (product.quantity <= product.product.stock) {
      const deleteproduct = await CM.deleteProductFromCart(cartId, product.product._id)
      if (deleteproduct.error) {
        req.logger.warning({ deleteproduct })
        res.status(400).send(deleteproduct)
      } else {
        req.logger.info({ message: 'Delete Single Product From Cart', deleteproduct })
      }

      try {
        const updateproduct = await PM.updateProduct(product.product._id, { stock: product.product.stock - product.quantity }, 'admin')
        if (updateproduct.error) {
          req.logger.warning({ updateproduct })
          res.status(400).send(updateproduct)
        } else {
          req.logger.info({ message: 'Update Product From Cart', updateproduct })
        }
      } catch (e) {
        req.logger.warning({ e })
        res.status(400).send(e)
      }

      number += 1
    }
  }

  if (number > 0) {
    const ticket = await TM.createTicket({
      purchase_datetime: Date.now(),
      amount: number,
      purchaser: req.user.email
    })
    req.ticket = ticket.result
    ticket.success ? res.status(200).send(ticket.result) : res.send({ ticket })
    // res.redirect(`/carts/${cartId}?ticket=${req.ticket._id}`);
  } else {
    res.send('We tried.')
  }
})

export default cartsRouter
