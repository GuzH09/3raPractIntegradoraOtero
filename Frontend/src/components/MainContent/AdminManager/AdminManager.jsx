import { useEffect, useState, useContext, useRef } from 'react'
import { AuthContext } from '../../../context/AuthContext'
import io from 'socket.io-client'
import { useNotification } from '../../../context/Notification'

const AdminManager = () => {
  const { profile } = useContext(AuthContext)
  const { setNotification } = useNotification()
  const [products, setProducts] = useState([])
  const [title, setTitle] = useState('')
  const [description, setDescription] = useState('')
  const [code, setCode] = useState('')
  const [price, setPrice] = useState('')
  const [stock, setStock] = useState('')
  const [category, setCategory] = useState('')
  const socketRef = useRef(null)

  useEffect(() => {
    // Initialize socket connection
    socketRef.current = io('http://localhost:8080', {
      withCredentials: true,
      reconnectionAttempts: 5, // Limit the number of reconnection attempts
      timeout: 10000 // Set timeout for the connection
    })

    // Emit user connection event
    if (profile) {
      socketRef.current.emit('productsConnect', profile)
    }

    // Receive messages from server
    socketRef.current.on('refreshProducts', (data) => {
      setProducts(data)
    })

    // Listen for new user notification
    socketRef.current.on('statusError', (data) => {
      setNotification('danger', JSON.stringify(data))
      console.log(data)
    })

    // Handle connection errors
    socketRef.current.on('connect_error', (err) => {
      console.error('Connection error:', err)
    })

    socketRef.current.on('connect_timeout', () => {
      console.error('Connection timeout')
    })

    socketRef.current.on('reconnect_attempt', (attempt) => {
      console.log('Reconnection attempt:', attempt)
    })

    socketRef.current.on('reconnect_failed', () => {
      console.error('Reconnection failed')
    })

    // Clean up socket connection on component unmount
    return () => {
      socketRef.current.disconnect()
    }
  }, [profile])

  const addProduct = () => {
    if (socketRef.current && profile) {
      const product = {
        title,
        description,
        code,
        price,
        stock,
        category
      }
      socketRef.current.emit('addProduct', product, profile)
      setTitle('')
      setDescription('')
      setCode('')
      setPrice('')
      setStock('')
      setCategory('')
    }
  }

  const deleteProduct = (productId) => {
    if (socketRef.current && profile) {
      socketRef.current.emit('deleteProduct', productId, profile)
    }
  }

  return (
        <div className="flex flex-column min-h-[80vh] p-3 items-center">

            <div className="flex flex-col items-center gap-3 w-full">
                <div className="flex flex-col items-center gap-1 w-1/3">
                    <label className="text-md">Nombre del Producto:</label>
                    <input
                        className="text-white font-thin rounded-md border-1 border-[#30363d] bg-[#21262d] w-3/4"
                        type="text"
                        value={title}
                        onChange={(e) => setTitle(e.target.value)}
                    />
                </div>

                <div className="flex flex-col items-center gap-1 w-1/3">
                    <label className="text-md">Descripcion del Producto:</label>
                    <input
                        className="text-white font-thin rounded-md border-1 border-[#30363d] bg-[#21262d] w-3/4"
                        type="text"
                        value={description}
                        onChange={(e) => setDescription(e.target.value)}
                    />
                </div>

                <div className="flex flex-col items-center gap-1 w-1/3">
                    <label className="text-md">Codigo:</label>
                    <input
                        className="text-white font-thin rounded-md border-1 border-[#30363d] bg-[#21262d] w-3/4"
                        type="text"
                        value={code}
                        onChange={(e) => setCode(e.target.value)}
                    />
                </div>

                <div className="flex flex-col items-center gap-1 w-1/3">
                    <label className="text-md">Precio:</label>
                    <input
                        className="text-white font-thin rounded-md border-1 border-[#30363d] bg-[#21262d] w-3/4"
                        type="number"
                        value={price}
                        onChange={(e) => setPrice(e.target.value)}
                    />
                </div>

                <div className="flex flex-col items-center gap-1 w-1/3">
                    <label className="text-md">Stock:</label>
                    <input
                        className="text-white font-thin rounded-md border-1 border-[#30363d] bg-[#21262d] w-3/4"
                        type="number"
                        value={stock}
                        onChange={(e) => setStock(e.target.value)}
                    />
                </div>

                <div className="flex flex-col items-center gap-1 w-1/3">
                    <label className="text-md">Categoria:</label>
                    <input
                        className="text-white font-thin rounded-md border-1 border-[#30363d] bg-[#21262d] w-3/4"
                        type="text"
                        value={category}
                        onChange={(e) => setCategory(e.target.value)}
                    />
                </div>

                <button onClick={addProduct} className="text-white rounded-md border-1 border-[#30363d] bg-[#21262d] p-1 text-sm w-1/6">Agregar Producto</button>
            </div>

            <div className="w-1/3 flex flex-row flex-wrap gap-2 items-center pt-4 bg-white">
                {products.map((prod) => (
                    <article key={prod._id} className="text-center flex flex-col">
                        <header>
                            <h2 className="font-medium py-2">{prod.title}</h2>
                        </header>
                        <section>
                            {prod.stock > 0 ? <p>Stock disponible: {prod.stock}</p> : <p>No hay stock.</p>}
                            <p>Precio: ${prod.price}</p>
                        </section>
                        <button
                            className="rounded bg-blue-50 px-2 py-1 text-xs font-medium text-red-700 ring-1 ring-red-600"
                            onClick={() => deleteProduct(prod._id)}
                        >
                            Eliminar Producto
                        </button>
                    </article>
                ))}
            </div>
        </div>
  )
}

export default AdminManager
