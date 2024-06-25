import TicketService from '../services/TicketService.js'

export default class TicketController {
// Patron de diseño Repository
  constructor () {
    this.ticketService = new TicketService()
  }

  async getAllTickets () {
    return this.ticketService.getAllTickets()
  }

  async getTicket (tid) {
    return this.ticketService.getTicket(tid)
  }

  async createTicket (ticket) {
    return this.ticketService.createTicket(ticket)
  }
}
