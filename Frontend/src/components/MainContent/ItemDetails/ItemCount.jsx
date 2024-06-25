import { useState, useContext } from 'react'
import { Link } from 'react-router-dom'
import { CartContext } from '../../../context/CartContext'

const ItemCount = ({ stock, initial, id, title }) => {
  const [quantity, setQuantity] = useState(initial)
  const [quantityAdded, setQuantityAdded] = useState(0)
  const { handleOnAdd } = useContext(CartContext)

  const increment = () => {
    if (quantity < stock) {
      setQuantity(quantity + 1)
    }
  }

  const decrement = () => {
    if (quantity > 1) {
      setQuantity(quantity - 1)
    }
  }

  return (
    <>
      <div className="flex flex-col items-center">
        <div className="flex flex-row text-center gap-2 w-full justify-center">
          <button
            className="rounded bg-blue-50 px-2 py-1 text-xs font-medium text-blue-700 ring-1 ring-blue-600"
            onClick={decrement}
          >
            -
          </button>
          <h4 className="font-bold">{quantity}</h4>
          <button
            className="rounded bg-blue-50 px-2 py-1 text-xs font-medium text-blue-700 ring-1 ring-blue-600"
            onClick={increment}
          >
            +
          </button>
        </div>
        <div className="py-3">
          {stock > 0
            ? (
            <button
              className="rounded bg-blue-50 px-2 py-1 text-xs font-medium text-blue-700 ring-1 ring-blue-600"
              onClick={() => {
                handleOnAdd(quantity, id, title)
                setQuantityAdded(quantity)
              }}
            >
              Agregar al carrito
            </button>
              )
            : (
            <button
              className="rounded bg-blue-50 px-2 py-1 text-xs font-medium text-red-700 ring-1 ring-red-600"
              disabled={true}
            >
              No hay Stock
            </button>
              )}
        </div>
      </div>

      {quantityAdded > 0 && (
        <div className="flex flex-col gap-2 text-center items-center">
          <Link
            className="rounded bg-blue-50 px-2 py-1 text-xs font-medium text-blue-700 ring-1 ring-blue-600"
            to="/"
          >
            Continuar Comprando
          </Link>
          <Link
            className="rounded bg-blue-50 px-2 py-1 text-xs font-medium text-blue-700 ring-1 ring-blue-600"
            to="/home/cart"
          >
            Terminar Compra
          </Link>
        </div>
      )}
    </>
  )
}

export default ItemCount
