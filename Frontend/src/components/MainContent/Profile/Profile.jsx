import { useContext } from 'react'
import { AuthContext } from '../../../context/AuthContext'
import '../SpinnerLoader/SpinnerLoader.css'
import { useNavigate } from 'react-router-dom'

const Profile = () => {
  const { setIsAuthenticated, profile } = useContext(AuthContext)
  const navigate = useNavigate()

  const handleSubmit = async () => {
    try {
      const response = await fetch('http://localhost:8080/api/sessions/logout', {
        method: 'GET',
        credentials: 'include'
      })

      if (response.ok) {
        // Handle the response from the backend
        setIsAuthenticated(false)
        navigate('/home')
      } else {
        console.error('Request failed with status', response.status)
      }
    } catch (error) {
      console.error(error)
    }
  }

  return (
        <>
            <div className="pt-4 px-12 min-h-[81vh]">
                <div className="flex justify-center">
                    <img src={'/images/profile_avatar.png'} className="h-48 w-48 object-contain" />
                </div>
                {profile
                  ? (
                    <div className="flex justify-center flex-col items-center gap-3">
                        <div>
                            <h2 className="text-center">First Name:</h2>
                            <h3 className="text-center">{profile.first_name}</h3>
                        </div>

                        <div>
                            <h2 className="text-center">Last Name:</h2>
                            <h3 className="text-center">{profile.last_name}</h3>
                        </div>

                        <div>
                            <h2 className="text-center">Email:</h2>
                            <h3 className="text-center">{profile.email}</h3>
                        </div>

                        <div>
                            <h2 className="text-center">Age:</h2>
                            <h3 className="text-center">{profile.age}</h3>
                        </div>

                        <div>
                            <h2 className="text-center">Role:</h2>
                            <h3 className="text-center">{profile.role}</h3>
                        </div>

                        <span className="rounded-md border-1 border-[#30363d] bg-[#21262d] p-1 text-sm w-2/6 text-center">
                            <button className="text-white" onClick={handleSubmit}>Cerrar sesion</button>
                        </span>
                    </div>
                    )
                  : (
                    <p>No profile data available</p>
                    )}
            </div>
        </>
  )
}

export default Profile
