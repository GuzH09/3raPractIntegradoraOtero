import { Navigate, Outlet, useLocation } from 'react-router-dom'
import { AuthContext } from '../context/AuthContext'
import './MainContent/SpinnerLoader/SpinnerLoader.css'
import { useContext, useEffect } from 'react'

const ProtectedRoute = ({ children, redirectTo, roleNeeded }) => {
  const { isAuthenticated, checkAuth, profile } = useContext(AuthContext)
  const location = useLocation()

  useEffect(() => {
    checkAuth()
  }, [location, checkAuth])

  if (isAuthenticated === undefined) {
    return (
            <div className="flex flex-row items-baseline justify-center pt-4 bg-white min-h-[50vh]">
                <div className="loader"></div>
            </div>
    )
  }

  if (!isAuthenticated) {
    console.log('No estas autenticado.')
    return <Navigate to={'/'} />
  } else {
    if (roleNeeded.includes(profile?.role)) {
      return children || <Outlet/>
    } else {
      return <Navigate to={redirectTo} />
    }
  }
}

export default ProtectedRoute
