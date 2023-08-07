import express from 'express'
import cors from 'cors'
import session from 'express-session'
import dotenv from 'dotenv'
import UserRoute from './routes/UserRoute.js'
import ProductRoute from './routes/ProductRoute.js'
import AuthRoute from './routes/AuthRoute.js'
import db from './config/Database.js'
import SequelizeStore from 'connect-session-sequelize'
dotenv.config();

const app = express()
app.use(cors({
    credentials: true,
    origin: 'http://localhost:3000'
}))

const sessionStore = SequelizeStore(session.Store)
const store = new sessionStore({
    db: db
})

// async function asyncDB() {
//     await db.sync();
// }
  
// asyncDB();

app.use(session({
    secret: process.env.SESS_SECRET,
    resave: false,
    saveUninitialized: true,
    store: store,
    cookie: {
        secure: 'auto'
    }
}))
// store.sync()
app.use(express.json())
app.use(UserRoute)
app.use(ProductRoute)
app.use(AuthRoute)



app.listen(process.env.APP_PORT, () => {
    console.log('Server up and running')
})