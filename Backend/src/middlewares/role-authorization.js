import CurrentUserDTO from '../DTOs/currentuser.dto.js'

export const roleauth = (roles) => {
  return (req, res, next) => {
    req.user = new CurrentUserDTO(req.user)
    if (roles.includes(req.user.role)) return next()
    req.logger.warning({ status: 'error', message: `Unauthorized: Expected one of roles ${roles} but got ${req.user.role}` })
    res.status(403).send({
      status: 'error',
      message: 'Unauthorized'
    })
  }
}
