import { Router } from 'express'
import passport from 'passport'

import ProductController from '../controllers/ProductController.js'
import MessageController from '../controllers/MessageController.js'
import CartController from '../controllers/CartController.js'
import productModel from '../models/productModel.js'
import { roleauth } from '../middlewares/role-authorization.js'
import TicketController from '../controllers/TicketController.js'

const viewsRouter = Router()
const PM = new ProductController()
const CHM = new MessageController()
const CM = new CartController()
const TM = new TicketController()

// Session Index
viewsRouter.get('/', passport.authenticate('jwt', { session: false, failureRedirect: '/login' }), (req, res) => {
  res.redirect('/profile')
})

// Session Login
viewsRouter.get('/login', (req, res) => {
  res.render(
    'login',
    {
      title: 'Session',
      style: 'session.css',
      failLogin: req.failLogin ?? false
    }
  )
})

// Session Register
viewsRouter.get('/register', (req, res) => {
  res.render(
    'register',
    {
      title: 'Session',
      style: 'session.css',
      failRegister: req.failRegister ?? false
    }
  )
})

// Show All Products
viewsRouter.get('/allproducts', passport.authenticate('jwt', { session: false, failureRedirect: '/login' }), async (req, res) => {
  const products = await PM.getProducts()
  res.render(
    'home',
    {
      products,
      user: req.user,
      isAdmin: req.user.role === 'admin',
      style: 'index.css'
    }
  )
})

// Session Profile
viewsRouter.get('/profile', passport.authenticate('jwt', { session: false, failureRedirect: '/login' }), (req, res) => {
  res.render(
    'profile',
    {
      title: 'Session',
      style: 'session.css',
      user: req.user,
      isAdmin: req.user.role === 'admin'
    }
  )
})

// Show Single Cart By Cart ID
viewsRouter.get('/carts/:cid', passport.authenticate('jwt', { session: false, failureRedirect: '/login' }), async (req, res) => {
  const cartId = req.params.cid
  const ticketId = req.query.ticket
  const ticketData = await TM.getTicket(ticketId)

  const cart = await CM.getCartById(cartId)
  res.render(
    'cart',
    {
      id: cart._id.toString(),
      products: cart.products,
      user: req.user,
      isAdmin: req.user.role === 'admin',
      ticket: ticketData,
      style: 'cart.css'
    }
  )
})

// Chat App with Websockets
viewsRouter.get('/chat', passport.authenticate('jwt', { session: false, failureRedirect: '/login' }), roleauth('user'), async (req, res) => {
  const messages = await CHM.getAllMessages()
  res.render(
    'chat',
    {
      messages,
      user: req.user,
      style: 'chat.css'
    }
  )
})

// Show All Products with Websockets - Manager dashboard for admin
viewsRouter.get('/realtimeproducts', passport.authenticate('jwt', { session: false, failureRedirect: '/login' }), roleauth('admin'), async (req, res) => {
  const products = await PM.getProducts()
  res.render(
    'realTimeProducts',
    {
      products,
      user: req.user,
      isAdmin: req.user.role === 'admin',
      style: 'realTimeProducts.css'
    }
  )
})

// Show All Products with Paginate
// viewsRouter.get('/products', async (req, res) => {
//     let { page = 1 } = req.query;
//     page = parseInt(page);
//     const result = await productModel.paginate({}, {page, limit: 5, lean: true});
//     const baseURL = "http://localhost:8080/products";
//     result.prevLink = result.hasPrevPage ? `${baseURL}?page=${result.prevPage}` : "";
//     result.nextLink = result.hasNextPage ? `${baseURL}?page=${result.nextPage}` : "";
//     result.title = "Productos";
//     result.isValid = !(page <= 0 || page > result.totalPages);
//     res.render(
//         "products",
//         {
//             result,
//             title: result.title,
//             style: "products.css"
//         }
//     );
// });

export default viewsRouter
