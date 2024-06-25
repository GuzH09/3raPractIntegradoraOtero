import MessageService from '../services/MessageService.js'

export default class MessageController {
// Patron de diseño Repository
  constructor () {
    this.messageService = new MessageService()
  }

  async getAllMessages () {
    return this.messageService.getAllMessages()
  }

  async addMessage (messageData) {
    return this.messageService.addMessage(messageData)
  }
}
