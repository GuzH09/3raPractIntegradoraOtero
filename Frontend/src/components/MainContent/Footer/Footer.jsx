const Footer = () => {
  return (
    <div className="flex flex-row w-full justify-around bg-zinc-600 px-56 py-3">
      <div className="">
        <h3 className="text-left text-gray-400 font-medium">ACERCA DE</h3>
        <p className="text-slate-300 font-extralight">Información</p>
        <p className="text-slate-300 font-extralight">Preguntas frecuentes</p>
      </div>

      <div className="">
        <h3 className="text-left text-gray-400 font-medium">SECCIONES</h3>
        <p className="text-slate-300 font-extralight">Favoritos</p>
        <p className="text-slate-300 font-extralight">Ofertas</p>
      </div>

      <div className="">
        <h3 className="text-left text-gray-400 font-medium">SEGUINOS</h3>
        <p className="text-slate-300 font-extralight">Facebook</p>
        <p className="text-slate-300 font-extralight">Instagram</p>
        <p className="text-slate-300 font-extralight">Twitter</p>
      </div>
    </div>
  )
}

export default Footer
