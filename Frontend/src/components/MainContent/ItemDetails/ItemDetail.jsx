import ItemCount from './ItemCount'
import '../SpinnerLoader/SpinnerLoader.css'

const ItemDetail = ({
  _id,
  title,
  thumbnails,
  category,
  description,
  price,
  stock
}) => {
  return (
    <article className="items-center flex flex-col">
      <header>
        <h2 className="font-bold">{title}</h2>
      </header>

      <picture className="h-72 w-42 p-3">
        <img className="h-full" src={thumbnails} alt={title} />
      </picture>

      <section className="text-center">
        <p>Categoria: {category}</p>
        <p>Descripcion: {description}</p>
        <p>Precio: ${price}</p>
        <p>Stock disponible: {stock}</p>
      </section>

      <footer className="py-3">
        <ItemCount initial={1} stock={stock} id={_id} title={title} />
      </footer>

    </article>
  )
}

export default ItemDetail
