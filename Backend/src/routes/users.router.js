import { Router } from 'express'
import passport from 'passport'
import jwt from 'jsonwebtoken'
import UserController from '../controllers/UserController.js'
// import CurrentUserDTO from '../DTOs/currentuser.dto.js'
import { roleauth } from '../middlewares/role-authorization.js'
import transporter from '../config/mailerConfig.js'
import { isValidPassword } from '../utils/functionsUtil.js'

const usersRouter = Router()
const SessionService = new UserController()

// API Register
usersRouter.post('/register', async (req, res) => {
  const result = await SessionService.registerUser(req.body)
  if (result.error) {
    req.logger.warning(result.error)
    return res.status(400).send(result)
  } else {
    req.logger.info(result)
    return res.status(200).send(result)
  }
})

// API Login
usersRouter.post('/login', async (req, res) => {
  const { email, password } = req.body
  const result = await SessionService.loginUser(email, password)
  if (result.error) {
    req.logger.warning(result)
    return res.status(400).send(result)
  } else {
    res.cookie('auth', result, { maxAge: 60 * 60 * 1000, httpOnly: true })
    req.logger.info(result)
    return res.status(200).send(result)
  }
})

// API Login with Github
usersRouter.get('/github', passport.authenticate('github', { scope: ['user:email'] }), (req, res) => {
  req.logger.info({ message: 'Success' })
  res.status(200).send({
    status: 'success',
    message: 'Success'
  })
})

// API Login Callback with Github
usersRouter.get('/githubcallback', passport.authenticate('github', {
  session: false,
  failureRedirect: 'http://localhost:3000/login'
}), (req, res) => {
  const token = jwt.sign(req.user, process.env.SECRET_OR_KEY, { expiresIn: '1h' })
  res.cookie('auth', token, { maxAge: 60 * 60 * 1000, httpOnly: true })
  req.logger.info({ message: 'Successful Callback' })
  return res.redirect('http://localhost:3000/home')
})

// API Current
usersRouter.get('/current', passport.authenticate('jwt', { session: false }), async (req, res) => {
  // Envia un DTO gracias a roleauth
  req.logger.info({ message: 'Used Current endpoint', user: req.user.email })
  res.status(200).send({
    user: req.user
  })
})

// API Logout
usersRouter.get('/logout', async (req, res) => {
  res.clearCookie('auth')
  req.logger.info({ message: 'Successful Logout' })
  res.status(200).send({
    status: 'success',
    message: 'Success'
  })
})

// API User ID
usersRouter.get('/:uid', passport.authenticate('jwt', { session: false }), roleauth(['admin']), async (req, res) => {
  const result = await SessionService.getUser(req.params.uid)
  if (result.error) {
    req.logger.warning(result)
    return res.status(400).send(result)
  } else {
    req.logger.info({ status: 'success', payload: result })
    return res.status(200).send({ status: 'success', payload: result })
  }
})

// API Upgrade User To Premium or viceversa
usersRouter.post('/premium/:uid', passport.authenticate('jwt', { session: false }), roleauth(['admin']), async (req, res) => {
  const user = await SessionService.getUser(req.params.uid)
  if (user.error) {
    req.logger.warning(user)
    return res.status(400).send(user)
  } else {
    req.logger.info({ user })
  }

  const result = (user.role === 'premium')
    ? await SessionService.updateUser(req.params.uid, 'user')
    : await SessionService.updateUser(req.params.uid, 'premium')

  if (result.error) {
    req.logger.warning(result)
    return res.status(400).send(result)
  } else {
    req.logger.info({ result })
    return res.status(200).send(result)
  }
})

// API Forgot Password
usersRouter.post('/forgot-password', async (req, res) => {
  const { email } = req.body
  const user = await SessionService.getUserByEmail(email)

  if (!user) {
    req.logger.warning({ status: 'Error', error: 'User with this email does not exist.' })
    return res.status(400).send({ error: 'User with this email does not exist.' })
  }

  const token = jwt.sign({ id: user._id }, process.env.SECRET_OR_KEY, { expiresIn: '10m' })
  const resetLink = `http://localhost:3000/reset-password/${token}` // Frontend URL

  const mailOptions = {
    from: 'GuzH Tech Store' + ' <' + process.env.EMAIL_USER + '>',
    to: email,
    subject: '[GuzH Tech Store] Password Reset',
    html: `<p>Click <a href="${resetLink}">here</a> to reset your password. This link will expire in 10 minutes.</p>`
  }

  try {
    await transporter.sendMail(mailOptions)
    req.logger.info({ status: 'Success', message: 'Password reset link sent to your email.' })
    res.status(200).send({ message: 'Password reset link sent to your email.' })
  } catch (error) {
    req.logger.warning({ status: 'Error', error: 'Error sending email.' })
    res.status(500).send({ error: 'Error sending email.' })
  }
})

// API Reset Password
usersRouter.post('/reset-password', async (req, res) => {
  const { token, password } = req.body

  try {
    const decoded = jwt.verify(token, process.env.SECRET_OR_KEY)
    const user = await SessionService.getUser(decoded.id)

    if (!user) {
      req.logger.warning({ status: 'Error', error: 'Invalid token or user does not exist.' })
      return res.status(400).send({ error: 'Invalid token or user does not exist.' })
    }
    // Check if the new password is the same as the old password
    if (isValidPassword(user, password)) {
      req.logger.warning({ status: 'Error', error: 'New password must be different from the old one.' })
      return res.status(400).send({ error: 'New password must be different from the old one.' })
    }

    await SessionService.resetPassword(decoded.id, password)
    req.logger.info({ status: 'Success', message: 'Password successfully reset.' })
    res.status(200).send({ message: 'Password successfully reset.' })
  } catch (error) {
    req.logger.warning({ status: 'Error', error })
    res.status(400).send({ error: 'Invalid or expired token.' })
  }
})

export default usersRouter
