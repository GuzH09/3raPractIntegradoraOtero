import { useState, useContext, useEffect } from 'react'
import { useNavigate, useParams } from 'react-router-dom'
import { AuthContext } from '../../context/AuthContext'
import { jwtDecode } from 'jwt-decode'

const ResetPasswordContainer = () => {
  // IF THE TOKEN HAS EXPIRED IT SHOULD NAVIGATE YOU TO FORGOT PASSWORD PAGE AGAIN
  const { token } = useParams()
  const [password, setPassword] = useState('')
  const [confirmPassword, setConfirmPassword] = useState('')
  const { isAuthenticated } = useContext(AuthContext)
  const navigate = useNavigate()

  const handleSubmit = async (e) => {
    e.preventDefault()

    if (password !== confirmPassword) {
      return alert("Passwords don't match.")
    }

    try {
      const response = await fetch('http://localhost:8080/api/sessions/reset-password', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ token, password })
      })
      if (response.ok) {
        alert('Your password has been reset.')
        return navigate('/home')
      } else {
        const data = await response.json()
        console.error('Request failed with status', response.status, data.error)
        alert(data.error)
      }
    } catch (error) {
      console.error('Error resetting password', error)
      alert('Error resetting password.')
    }
  }

  useEffect(() => {
    if (isAuthenticated) {
      // Redirect to home if already authenticated
      return navigate('/home')
    }

    try {
      const decodedToken = jwtDecode(token)
      const currentTime = Date.now() / 1000 // Current time in seconds

      if (decodedToken.exp < currentTime) {
        alert('The URL has expired. Please request a new password reset.')
        return navigate('/forgot-password')
      }
    } catch (error) {
      console.error('Invalid token:', error)
      navigate('/forgot-password')
    }
  }, [isAuthenticated, navigate, token])

  return (
    <div className="bg-[#0d1117] w-full h-screen flex items-center flex-col justify-center gap-4">
      <div className="h-[120px] w-[120x] text-center flex flex-col justify-center gap-2">
        <img src={'/images/logo.png'} className="h-full object-contain" />
        <h2 className="text-white">GuzH Tech Store</h2>
      </div>
      <div className="rounded-md border-1 border-[#30363d] flex flex-col items-center py-2 gap-2 w-1/3">
        <form className="flex flex-col items-center gap-3 w-full" onSubmit={handleSubmit}>

          <div className="flex flex-col items-center gap-1 w-full">
            <label className="text-white text-md">Nueva Password:</label>
            <input
              className="text-white font-thin rounded-md border-1 border-[#30363d] bg-[#21262d] w-3/4 px-1"
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder='Ingrese su nueva password'
              required
            />
          </div>

          <div className="flex flex-col items-center gap-1 w-full">
            <label className="text-white text-md">Confirme Nueva Password:</label>
            <input
              className="text-white font-thin rounded-md border-1 border-[#30363d] bg-[#21262d] w-3/4 px-1"
              type="password"
              value={confirmPassword}
              onChange={(e) => setConfirmPassword(e.target.value)}
              placeholder='Confirme su nueva password'
              required
            />
          </div>

          <button type="submit" className="text-white rounded-md border-1 border-[#30363d] bg-[#21262d] p-1 text-sm w-2/6">Reestablecer contraseña</button>
        </form>
      </div>
    </div>
  )
}

export default ResetPasswordContainer
