import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom'
import ErrorPage from './components/ErrorPage/ErrorPage'
import LoginContainer from './components/Login/LoginContainer'
import RegisterContainer from './components/Login/RegisterContainer'
import MainContent from './components/MainContent/MainContent'
import { AuthProvider } from './context/AuthContext'
import ForgotPasswordContainer from './components/Login/ForgotPasswordContainer'
import ResetPasswordContainer from './components/Login/ResetPasswordContainer'

function App () {
  return (
    <>
      <BrowserRouter>
        <AuthProvider>
          <Routes>
            <Route path="/" element={<Navigate to="/login" />} />
            <Route path="/login" element={<LoginContainer />} />
            <Route path="/register" element={<RegisterContainer />} />
            <Route path="/forgot-password" element={<ForgotPasswordContainer />} />
            <Route path="/reset-password/:token" element={<ResetPasswordContainer />} />
            <Route path="/home/*" element={<MainContent />} />
            <Route path="*" element={<ErrorPage />} />
          </Routes>
        </AuthProvider>
      </BrowserRouter>
    </>
  )
}

export default App
