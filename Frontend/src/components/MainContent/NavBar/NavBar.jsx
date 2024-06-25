import { NavLink, Link } from 'react-router-dom'
import { useContext } from 'react'
import { AuthContext } from '../../../context/AuthContext'
import AdminWidget from './AdminManagerWidget'
import ProfileWidget from './ProfileWidget'
import CartWidget from './CartWidget'
import ChatWidget from './ChatWidget'

const NavBar = () => {
  const { profile } = useContext(AuthContext)

  return (
    <nav className="sticky w-full shadow-md bg-gray-100">
      <div className="flex flex-row justify-between items-center h-16 px-56">
        <div className="w-1/3">
          <Link to="/home" className="flex flex-row items-center">
            <div className="h-16 w-16 p-2">
              <img src={'/images/logo.png'} className="object-contain w-full" />
            </div>
            <h3 className="text-[#21232A] hover:text-gray-400 text-sm text-left">
              GuzH Tech Store
            </h3>
          </Link>
        </div>

        <div className="flex flex-row text-[#21232A] text-sm w-1/3 justify-center gap-8">
          <NavLink to={'/home/category/celular'}>Celulares</NavLink>
          <NavLink to={'/home/category/tablet'}>Tablets</NavLink>
          <NavLink to={'/home/category/notebook'}>Notebooks</NavLink>
        </div>

        <div className="w-1/3 flex items-center justify-end gap-3">
            {profile && <ChatWidget />}
            {profile && (profile.role === 'admin' || profile.role === 'premium') && <AdminWidget />}
            {profile && <ProfileWidget />}
            {profile && <CartWidget />}
        </div>
      </div>
    </nav>
  )
}

export default NavBar
