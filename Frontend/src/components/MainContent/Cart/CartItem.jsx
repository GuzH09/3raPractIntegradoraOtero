import { useContext } from 'react'
import { CartContext } from '../../../context/CartContext'

const CartItem = ({ product, quantity }) => {
  const { handleOnRemove } = useContext(CartContext)

  return (
    <article className="flex w-full justify-between gap-3 items-center rounded bg-blue-50 py-4 px-4 my-2 text-xs font-medium text-blue-700 ring-1 ring-blue-600">
      <picture className="h-16">
        <img
          className="h-full w-full object-contain"
          src={product.thumbnails[0]}
          alt={product.title}
        />
      </picture>

      <h2 className="w-1/6 font-bold text-center">{product.title}</h2>

      <h3 className="w-1/6 text-center">Cantidad: {quantity}</h3>

      <h3 className="w-1/6 text-center">Precio x Unidad: ${product.price}</h3>

      <h3 className="w-1/6 text-center">Subtotal: ${product.price * quantity}</h3>

      <button
        className="rounded bg-blue-50 py-2 px-2 my-2 text-xs font-medium text-blue-700 ring-1 ring-blue-600"
        onClick={() => handleOnRemove(product._id)}
      >
        X
      </button>
    </article>
  )
}

export default CartItem
