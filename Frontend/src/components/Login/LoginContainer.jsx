import { useState, useContext, useEffect } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { AuthContext } from '../../context/AuthContext'

const LoginContainer = () => {
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const { isAuthenticated, setIsAuthenticated } = useContext(AuthContext)
  const navigate = useNavigate()

  const handleSubmit = async (e) => {
    e.preventDefault()

    try {
      const response = await fetch('http://localhost:8080/api/sessions/login', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ email, password }),
        credentials: 'include'
      })

      if (response.ok) {
        // Handle the response from the backend
        setIsAuthenticated(true)
        navigate('/home')
      } else {
        console.error('Request failed with status', response.status)
      }
    } catch (error) {
      console.error(error)
    }
  }

  const handleButtonClick = async () => {
    window.location.href = 'http://localhost:8080/api/sessions/github'
  }

  useEffect(() => {
    if (isAuthenticated) {
      // Redirect to home if already authenticated
      return navigate('/home')
    }
  }, [isAuthenticated, navigate])

  return (
    <div className="bg-[#0d1117] w-full h-screen flex items-center flex-col justify-center gap-4">
      <div className="h-[120px] w-[120x] text-center flex flex-col justify-center gap-2">
        <img src={'/images/logo.png'} className="h-full object-contain" />
        <h2 className="text-white">GuzH Tech Store</h2>
      </div>
      <div className="rounded-md border-1 border-[#30363d] flex flex-col items-center py-2 gap-2 w-1/3">

        <form className="flex flex-col items-center gap-3 w-full" onSubmit={handleSubmit}>

          <div className="flex flex-col items-center gap-1 w-full">
            <label className="text-white text-md">Email:</label>
            <input
              className="text-white font-thin rounded-md border-1 border-[#30363d] bg-[#21262d] w-3/4"
              type="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
            />
          </div>

          <div className="flex flex-col items-center gap-1 w-full">
            <label className="text-white text-md">Password:</label>
            <input
              className="text-white font-thin rounded-md border-1 border-[#30363d] bg-[#21262d] w-3/4"
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
            />
          </div>

          <button type="submit" className="text-white rounded-md border-1 border-[#30363d] bg-[#21262d] p-1 text-sm w-2/6">Iniciar sesion</button>
        </form>

        <span className="rounded-md border-1 border-[#30363d] bg-[#21262d] p-1 text-sm w-2/6 text-center">
          <a href="/register" target="_self" className="text-white">Registrarse</a>
        </span>

        <span className="rounded-md border-1 border-[#30363d] bg-[#21262d] p-1 text-sm w-2/6 text-center">
          <button className="text-white" onClick={handleButtonClick}>Ingresar con Github</button>
        </span>

        <Link to="/forgot-password" className="p-1 text-sm text-white text-center">¿Olvidaste tu contraseña?</Link>

      </div>
    </div>
  )
}

export default LoginContainer
