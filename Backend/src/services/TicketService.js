import ticketModel from '../models/TicketModel.js'

export default class TicketService {
  // Patron de diseño DAO
  async getAllTickets () {
    try {
      const tickets = await ticketModel.find().lean()
      const ticketsWithStrIds = tickets.map(ticket => {
        return {
          ...ticket,
          _id: ticket._id.toString()
        }
      })
      return ticketsWithStrIds
    } catch (error) {
      return { error: error.message }
    }
  }

  async getTicket (tid) {
    try {
      const ticket = await ticketModel.findOne({ _id: tid }).lean()
      if (!ticket) return { error: 'Error getting ticket.' }
      return ticket
    } catch (error) {
      return { error: 'Ticket doesnt exists.' }
    }
  }

  async createTicket (ticket) {
    try {
      const { purchase_datetime, amount, purchaser } = ticket
      const result = await ticketModel.create({ purchase_datetime, amount, purchaser })
      return { success: 'Ticket created.', result }
    } catch (error) {
      return { error: error.message }
    }
  }
}
