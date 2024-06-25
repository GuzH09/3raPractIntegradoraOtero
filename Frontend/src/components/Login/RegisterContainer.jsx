import { useState, useContext, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import { AuthContext } from '../../context/AuthContext'

const RegisterContainer = () => {
  const [first_name, setFirstname] = useState('')
  const [last_name, setLastname] = useState('')
  const [email, setEmail] = useState('')
  const [age, setAge] = useState('')
  const [password, setPassword] = useState('')
  const { isAuthenticated } = useContext(AuthContext)
  const navigate = useNavigate()

  const handleSubmit = async (e) => {
    e.preventDefault()

    try {
      const response = await fetch('http://localhost:8080/api/sessions/register', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ first_name, last_name, email, age, password }),
        credentials: 'include'
      })

      if (response.ok) {
        navigate('/login')
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
      <div className="rounded-md border-1 border-[#30363d] flex flex-col items-center py-2 gap-3 w-1/3">

        <form className="flex flex-col items-center gap-3 w-full" onSubmit={handleSubmit}>

          <div className="flex flex-col items-center gap-1 w-full">
            <label className="text-white text-md">First Name:</label>
            <input
              className="text-white font-thin rounded-md border-1 border-[#30363d] bg-[#21262d] w-3/4"
              type="text"
              value={first_name}
              onChange={(e) => setFirstname(e.target.value)}
            />
          </div>

          <div className="flex flex-col items-center gap-1 w-full">
            <label className="text-white text-md">Last Name:</label>
            <input
              className="text-white font-thin rounded-md border-1 border-[#30363d] bg-[#21262d] w-3/4"
              type="text"
              value={last_name}
              onChange={(e) => setLastname(e.target.value)}
            />
          </div>

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
            <label className="text-white text-md">Age:</label>
            <input
              className="text-white font-thin rounded-md border-1 border-[#30363d] bg-[#21262d] w-3/4"
              type="number"
              value={age}
              onChange={(e) => setAge(e.target.value)}
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

          <button type="submit" className="text-white rounded-md border-1 border-[#30363d] bg-[#21262d] p-1 text-sm w-2/6">Register</button>
        </form>

        <span className="text-white text-sm flex gap-1">
          <p>¿Already have an account?</p>
          <a href="/login" target="_self"><strong>Login</strong></a>
        </span>

      </div>
    </div>
  )
}

export default RegisterContainer
