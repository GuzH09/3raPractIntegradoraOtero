import winston from 'winston'
import __dirname from './utils/constantsUtil.js'

const customErrLevels = {
  levels: {
    fatal: 0,
    error: 1,
    warning: 2,
    info: 3,
    http: 4,
    debug: 5
  }
}

const devLogger = winston.createLogger({
  levels: customErrLevels.levels,
  transports: [
    new winston.transports.Console({ level: 'debug' })
  ]
})

const prodLogger = winston.createLogger({
  levels: customErrLevels.levels,
  transports: [
    new winston.transports.Console({ level: 'info' }),
    new winston.transports.File({ level: 'error', filename: `${__dirname}/../logs/errors.log` })
  ]
})

const addLogger = (req, res, next) => {
  req.logger = devLogger
  req.logger.http(`${new Date().toDateString()} ${req.method} ${req.url}`)
  next()
}

console.log('Logger loaded')

export default addLogger
