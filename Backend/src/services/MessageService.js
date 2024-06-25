import messageModel from '../models/messageModel.js'

export default class MessageService {
  // Patron de diseño DAO
  async getAllMessages () {
    try {
      const messages = await messageModel.find().lean()
      const messagesWithStrIds = messages.map(message => {
        return {
          ...message,
          _id: message._id.toString()
        }
      })
      return messagesWithStrIds
    } catch (error) {
      return { error: error.message }
    }
  }

  async addMessage (messageData) {
    try {
      await messageModel.create({ user: messageData.user, message: messageData.message })
      return { success: 'Message added.' }
    } catch (error) {
      return { error: error.message }
    }
  }
}
