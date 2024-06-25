import { useContext, useEffect } from 'react'
import { Link } from 'react-router-dom'

import cart from './assets/shoppingcart.svg'
import { CartContext } from '../../../context/CartContext'

const CartWidget = () => {
  const { totalQuantity, fetchCartFromUser } = useContext(CartContext)

  useEffect(() => {
    fetchCartFromUser()
  }, [fetchCartFromUser])

  return (
    <Link to="/home/cart">
      <div className="flex flex-row items-center justify-end">
        <p className="font-bold text-[#21232A] text-sm">{totalQuantity}</p>
        <img src={cart} alt="cart-widget" />
      </div>
    </Link>
  )
}

export default CartWidget
