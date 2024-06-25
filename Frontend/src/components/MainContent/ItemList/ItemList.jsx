import Item from './Item'

const ItemList = ({ products }) => {
  return (
    <div className="flex flex-row flex-wrap justify-evenly items-center pt-4 bg-white">
      {products.map((prod) => (
        <Item key={prod.id} {...prod} />
      ))}
    </div>
  )
}

export default ItemList
