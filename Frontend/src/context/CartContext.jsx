import { createContext, useContext, useState, useCallback } from 'react'
import { AuthContext } from './AuthContext'
import { useNotification } from './Notification'

export const CartContext = createContext()

export const CartProvider = ({ children }) => {
  const { profile } = useContext(AuthContext)
  const { setNotification } = useNotification()
  const [ticket, setTicket] = useState({})
  const [cart, setCart] = useState([])
  const [total, setTotal] = useState(0)
  const [totalQuantity, setTotalQuantity] = useState(0)

  const fetchCartFromUser = useCallback(async () => {
    try {
      const responseCart = await fetch(`http://localhost:8080/api/carts/${profile.cart[0]}`, {
        credentials: 'include'
      })

      if (responseCart.ok) {
        const dataCart = await responseCart.json()
        // Process the data to include full URLs for thumbnails
        const processedData = dataCart.carts.products.map((product) => {
          const baseURL = 'http://localhost:8080/static/img/'
          return {
            ...product,
            product: {
              ...product.product,
              thumbnails: product.product.thumbnails.map((thumbnail) =>
                baseURL + thumbnail.split('public\\img\\')[1]
              )
            }
          }
        })

        setCart(processedData)
        setTotalQuantity(dataCart.carts.products.length)
      } else {
        setCart([])
        setTotalQuantity(0)
      }
    } catch (error) {
      console.error(error)
    }
  }, [profile])

  const handleOnRemove = async (id) => {
    try {
      await fetch(`http://localhost:8080/api/carts/${profile.cart[0]}/product/${id}/delete`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        credentials: 'include'
      })
      fetchCartFromUser()
    } catch (error) {
      console.error(error)
    }
  }

  const handleOnAdd = async (quantity, id, title) => {
    try {
      const response = await fetch(`http://localhost:8080/api/carts/${profile.cart[0]}/product/${id}`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        credentials: 'include'
      })

      if (response.ok) {
        const responseQuantity = await fetch(`http://localhost:8080/api/carts/${profile.cart[0]}/product/${id}`, {
          method: 'PUT',
          headers: {
            'Content-Type': 'application/json'
          },
          body: JSON.stringify({ quantity }),
          credentials: 'include'
        })
        if (responseQuantity.ok) {
          setNotification('success', `Se agregaron ${quantity} de ${title}`)
          fetchCartFromUser()
        } else {
          throw new Error('Request failed with status', responseQuantity.status)
        }
      } else {
        setNotification('danger', 'Premium users cannot add their own products to the cart.')
        console.error('Request failed with status', response.status)
      }
    } catch (error) {
      console.error(error)
    }
  }

  const handleOnCheckout = async () => {
    try {
      const response = await fetch(`http://localhost:8080/api/carts/${profile.cart[0]}/purchase/`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        credentials: 'include'
      })

      if (response.ok) {
        const dataCheckout = await response.json()
        setTicket(dataCheckout)
      } else {
        console.log(response)
      }

      fetchCartFromUser()
    } catch (error) {
      console.error(error)
    }
  }

  return (
    <CartContext.Provider
      value={{
        cart,
        setCart,
        total,
        setTotal,
        totalQuantity,
        setTotalQuantity,
        ticket,
        setTicket,
        fetchCartFromUser,
        handleOnRemove,
        handleOnAdd,
        handleOnCheckout
      }}
    >
      {children}
    </CartContext.Provider>
  )
}
