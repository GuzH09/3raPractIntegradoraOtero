import mongoose from 'mongoose'

const ticketsCollection = 'tickets'

const ticketSchema = mongoose.Schema({
  code: {
    type: String,
    unique: true,
    require: true,
    default: function () {
      // Genera un código de ticket único
      return `TICKET-${Math.random().toString(36).substr(2, 6).toUpperCase()}`
    }
  },
  purchase_datetime: {
    type: Date,
    require: true
  },
  amount: {
    type: Number,
    require: true
  },
  purchaser: {
    type: String,
    require: true
  }
})

const ticketModel = mongoose.model(ticketsCollection, ticketSchema)

export default ticketModel
