import { useEffect, useContext } from 'react'
import { Link } from 'react-router-dom'

import { AuthContext } from '../../../context/AuthContext'
import { CartContext } from '../../../context/CartContext'
import CartItem from './CartItem'
// import Checkout from "../Checkout/Checkout";

const Cart = () => {
  const { cart, totalQuantity, fetchCartFromUser, handleOnCheckout } = useContext(CartContext)
  const { profile } = useContext(AuthContext)

  useEffect(() => {
    fetchCartFromUser()
  }, [fetchCartFromUser])

  if (totalQuantity === 0) {
    return (
      <div className="py-4 flex flex-col items-center min-h-[81vh]">
        <h1>No hay items en el carrito</h1>
        <Link
          to="/"
          className="rounded bg-blue-50 py-2 px-2 my-2 text-xs font-medium text-blue-700 ring-1 ring-blue-600"
        >
          Productos
        </Link>
      </div>
    )
  }

  return (
    <div className="pt-4 px-56 flex flex-column items-center min-h-[81vh]">
      {cart
        ? (
            cart.map((p) => (
          <CartItem key={p._id} {...p} cartId={profile.cart[0]} />
            ))
          )
        : (
        <p>No profile data available</p>
          )}
      {/* <h3 className="font-bold">Total: ${total}</h3>
      <button
        className="rounded bg-blue-50 py-2 px-2 my-2 text-xs font-medium text-blue-700 ring-1 ring-blue-600"
        onClick={() => clearCart()}
      >
        Limpiar carrito
      </button> */}
      <Link
        className="rounded bg-blue-50 py-2 px-2 my-2 text-xs font-medium text-blue-700 ring-1 ring-blue-600"
        onClick={() => handleOnCheckout(profile.cart[0])}
        to={'/home/Checkout/'}
      >
        Checkout
      </Link>
    </div>
  )
}

export default Cart
