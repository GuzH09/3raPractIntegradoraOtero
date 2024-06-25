import MessageService from './services/MessageService.js'
import ProductService from './services/ProductService.js'
const PM = new ProductService()
const CHM = new MessageService()

export default (io) => {
  io.on('connection', socket => {
    console.log('Nuevo cliente conectado -----> ', socket.id)

    socket.on('addProduct', async (data, profile) => {
      // Get Product Data
      const { title, description, code, price, stock, category } = data

      const thumbnails = []
      // Status is true by default
      // Thumbnails is not required, [] by default
      if (profile.role !== 'admin' && profile.role !== 'premium') {
        io.emit('statusError', 'Unauthorized')
      } else {
        const owner = (profile.role === 'premium') ? profile.email : 'admin'
        const newObjectData = { title, description, code, price, stock, category, thumbnails, owner }
        const result = await PM.addProduct(newObjectData)

        if (result.success) {
          const products = await PM.getProducts()
          io.emit('refreshProducts', products)
        } else {
          io.emit('statusError', result)
        }
      }
    })

    socket.on('deleteProduct', async (data, profile) => {
      // Delete Existing Product
      // Get Product Id
      if (profile.role !== 'admin' && profile.role !== 'premium') {
        io.emit('statusError', 'Unauthorized')
      } else {
        const owner = (profile.role === 'premium') ? profile.email : 'admin'
        const productId = data
        const result = await PM.deleteProduct(productId, owner)
        if (result.success) {
          const products = await PM.getProducts()
          io.emit('refreshProducts', products)
        } else {
          io.emit('statusError', result)
        }
      }
    })

    socket.on('productsConnect', async () => {
      const products = await PM.getProducts()
      io.emit('refreshProducts', products)
    })

    socket.on('message', async (data) => {
      await CHM.addMessage(data)
      const messages = await CHM.getAllMessages()
      io.emit('messagesLogs', messages)
    })

    socket.on('userConnect', async (data) => {
      const messages = await CHM.getAllMessages()
      socket.emit('messagesLogs', messages)
      socket.broadcast.emit('newUser', data)
    })
  })
}
