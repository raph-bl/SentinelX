function isAuthenticated (req, res, next) {
  if (req.session && req.session.userId) return next()
  res.redirect('/login')
}

function isAdmin (req, res, next) {
  if (req.session && req.session.role === 'admin') return next()
  res.status(403).send('Accès refusé')
}

module.exports = { isAuthenticated, isAdmin }
