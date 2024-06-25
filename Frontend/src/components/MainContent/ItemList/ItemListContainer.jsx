import { useState, useEffect } from 'react'
import { useNotification } from '../../../context/Notification'
import { useParams } from 'react-router-dom'
import ItemList from './ItemList'
import BrandHeader from './BrandHeader'
import '../SpinnerLoader/SpinnerLoader.css'

const ItemListContainer = () => {
  const [products, setProducts] = useState([])
  const [loading, setLoading] = useState(false)
  const { setNotification } = useNotification()
  const { categoryId } = useParams()

  useEffect(() => {
    const fetchData = async () => {
      try {
        setLoading(true)

        const response = categoryId
          ? await fetch(
              `http://localhost:8080/api/products?limit=100&category=${categoryId}`
          )
          : await fetch('http://localhost:8080/api/products?limit=100')

        if (!response.ok) {
          throw new Error('Network response was not ok')
        }
        const data = await response.json()

        // Process the data to include full URLs for thumbnails
        const processedData = data.payload.map((product) => {
          const baseURL = 'http://localhost:8080/static/img/'
          return {
            ...product,
            thumbnails: product.thumbnails.map(
              (thumbnail) => baseURL + thumbnail.split('public\\img\\')[1]
            )
          }
        })

        setProducts(processedData)
      } catch (error) {
        setNotification('danger', 'No es posible cargar los productos')
        console.error(error)
      } finally {
        setLoading(false)
      }
    }
    fetchData()
  }, [categoryId, setNotification])

  return (
    <>
      <BrandHeader />
      <div className="px-56 py-3 bg-zinc-200 h-full">
        <div className="pb-3">
          {categoryId
            ? (
            <h1 className="text-center font-medium">{`Productos por ${categoryId}`}</h1>
              )
            : (
            <h1 className="text-center font-medium">{'Todos nuestros productos'}</h1>
              )}
        </div>
        {loading
          ? (
          <div className="flex flex-row items-baseline justify-center pt-4 bg-white min-h-[50vh]">
            <div className="loader"></div>
          </div>
            )
          : (
          <ItemList products={products} />
            )}
      </div>
    </>
  )
}

export default ItemListContainer
