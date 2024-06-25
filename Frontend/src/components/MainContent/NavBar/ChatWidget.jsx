import chat from './assets/chat.svg'
import { Link } from 'react-router-dom'

const ChatWidget = () => {
  return (
    <Link to="/home/chat">
        <img className="h-7 w-7" src={chat} alt="chat-widget" />
    </Link>
  )
}

export default ChatWidget
