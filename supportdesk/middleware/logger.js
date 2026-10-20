// Logging middleware skeleton -- implement to make SupportDesk observable.
//
// Mount in app.js AFTER the session middleware and BEFORE the routers:
//   app.use(require('./middleware/logger'))
//
// Emit structured events following the schema agreed in your CONTRACT.md.
// Which fields to capture, from which part of each request, and how to detect
// failed authentication are yours to determine.

function logger(req, res, next) {
  // TODO: implement
  next()
}

module.exports = logger
