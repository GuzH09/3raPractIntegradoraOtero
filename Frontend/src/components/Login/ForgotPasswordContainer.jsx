import { useState, useContext, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import { AuthContext } from '../../context/AuthContext'

const ForgotPasswordContainer = () => {
  const [email, setEmail] = useState('')
  const { isAuthenticated } = useContext(AuthContext)
  const navigate = useNavigate()

  const handleSubmit = async (e) => {
    e.preventDefault()

    try {
      const response = await fetch('http://localhost:8080/api/sessions/forgot-password', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ email }),
        credentials: 'include'
      })

      if (response.ok) {
        alert('Password reset link sent to your email.')
        return navigate('/home')
      } else {
        console.error('Request failed with status', response.status)
      }
    } catch (error) {
      console.error(error)
    }
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
            <label className="text-white text-md">Account Email:</label>
            <input
              className="text-white font-thin rounded-md border-1 border-[#30363d] bg-[#21262d] w-3/4 px-1"
              type="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              placeholder='Ingrese su email'
              required
            />
          </div>

          <button type="submit" className="text-white rounded-md border-1 border-[#30363d] bg-[#21262d] p-1 text-sm w-2/6">Reestablecer contraseña</button>
        </form>
      </div>
    </div>
  )
}

export default ForgotPasswordContainer
