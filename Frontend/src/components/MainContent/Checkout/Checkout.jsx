import { useContext } from 'react'
import { CartContext } from '../../../context/CartContext'

const Checkout = () => {
  const { ticket } = useContext(CartContext)

  return (
    <div className="pt-4 px-56 flex flex-column items-center min-h-[81vh]">
      { ticket && (
        <div>
          <p>{ticket.code}</p>
          <p>{ticket.purchase_datetime}</p>
          <p>{ticket.amount}</p>
          <p>{ticket.purchaser}</p>
        </div>
      )}
    </div>
  )
}

export default Checkout
