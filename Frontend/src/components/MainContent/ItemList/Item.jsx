import { Link } from 'react-router-dom'
// import useProductImage from "../../hooks/useProductImage";

const Item = ({ id, title, thumbnails, price, stock }) => {
  // const { imgURL, loadingItem } = useProductImage(img, false);

  return (
    <article className="text-center flex flex-col">
      <header>
        <h2 className="font-medium py-2">{title}</h2>
      </header>

      <picture className="h-56 w-60 p-3">
        <img
          className="h-full w-full object-contain"
          src={thumbnails[0]}
          alt={title}
        />
      </picture>

      <section>
        {stock > 0 ? <p>Stock disponible: {stock}</p> : <p>No hay stock.</p>}
        <p>Precio: ${price}</p>
      </section>

      <footer className="py-3">
        {stock > 0
          ? (
          <Link
            className="rounded bg-blue-50 px-2 py-1 text-xs font-medium text-blue-700 ring-1 ring-blue-600"
            to={`/home/item/${id}`}
          >
            Ver Detalle
          </Link>
            )
          : (
          <button
            className="rounded bg-blue-50 px-2 py-1 text-xs font-medium text-red-700 ring-1 ring-red-600"
            disabled={true}
          >
            No hay Stock
          </button>
            )}
      </footer>
    </article>
  )
}

export default Item
