import profile from './assets/profile.svg'
import { Link } from 'react-router-dom'

const ProfileWidget = () => {
  return (
    <Link to="/home/profile">
        <img src={profile} alt="profile-widget" />
    </Link>
  )
}

export default ProfileWidget
