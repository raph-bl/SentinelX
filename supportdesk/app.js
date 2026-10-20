const express = require('express')
const session = require('express-session')
const path = require('path')

const db = require('./database/db')
const seed = require('./database/seed')
const { isAuthenticated } = require('./middleware/auth')

const authRouter = require('./routes/auth')
const ticketsRouter = require('./routes/tickets')
const adminRouter = require('./routes/admin')
const profileRouter = require('./routes/profile')
const kbRouter = require('./routes/kb')

const app = express()
const PORT = process.env.PORT || 3000

// Read real client IP from X-Forwarded-For when behind a proxy/Docker bridge
app.set('trust proxy', true)

seed()

app.set('view engine', 'ejs')
app.set('views', path.join(__dirname, 'views'))

app.use(express.urlencoded({ extended: false }))
app.use(express.static(path.join(__dirname, 'public')))

app.use(session({
  secret: process.env.SESSION_SECRET || 'dev-secret',
  resave: false,
  saveUninitialized: false
}))

app.get('/', (req, res) => res.redirect('/login'))

app.use('/', authRouter)
app.use('/tickets', ticketsRouter)
app.use('/admin', adminRouter)
app.use('/profile', profileRouter)
app.use('/kb', kbRouter)

app.get('/dashboard', isAuthenticated, (req, res) => {
  const user = {
    id: req.session.userId,
    username: req.session.username,
    role: req.session.role,
    display_name: req.session.display_name,
    theme: req.session.theme
  }
  const total = db.prepare('SELECT COUNT(*) as n FROM tickets').get().n
  const open = db.prepare("SELECT COUNT(*) as n FROM tickets WHERE status = 'open'").get().n
  const inProgress = db.prepare("SELECT COUNT(*) as n FROM tickets WHERE status = 'in_progress'").get().n
  const urgent = db.prepare("SELECT COUNT(*) as n FROM tickets WHERE priority = 'urgent'").get().n
  const recent = db.prepare(`
    SELECT t.*, u.username as creator_name
    FROM tickets t LEFT JOIN users u ON t.created_by = u.id
    ORDER BY t.created_at DESC LIMIT 5
  `).all()
  res.render('dashboard', { user, stats: { total, open, inProgress, urgent }, recent })
})

// Global error handler -- instrument this to capture 500 events
app.use((err, req, res, next) => {
  res.status(500).send('Internal server error')
})

app.listen(PORT, () => {
  console.log(`SupportDesk running on http://localhost:${PORT}`)
})
