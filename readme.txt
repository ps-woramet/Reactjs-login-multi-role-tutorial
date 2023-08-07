1. create backend folder

    cd to backend terminal > npm init -y > npm i argon2 cors dotenv express express-session mysql2 sequelize nodemon

    express: Express เป็นเฟรมเวิร์คแอปพลิเคชันสำหรับ Node.js ที่ใช้ในการสร้างเว็บเซิร์ฟเวอร์และ API อย่างมีประสิทธิภาพและง่ายดาย

    mysql2: แพ็คเกจนี้เป็น MySQL driver สำหรับ Node.js ที่ช่วยให้แอปพลิเคชันของคุณสามารถเชื่อมต่อกับฐานข้อมูล MySQL และดำเนินการต่างๆ เช่น คิวรี่ (query) และการอัปเดตข้อมูลได้

    sequelize: Sequelize เป็นไลบรารี Object-Relational Mapping (ORM) สำหรับ Node.js ที่ให้ชั้นข้อมูลของคุณแปลงเป็นวัตถุ JavaScript แทนการใช้คำสั่ง SQL ตรงๆ เพื่อติดต่อกับฐานข้อมูล

    argon2: Argon2 เป็นอัลกอริทึมสำหรับการแฮชรหัสผ่าน ใช้ในการแฮชและยืนยันความถูกต้องของรหัสผ่านในแอปพลิเคชันของคุณอย่างปลอดภัย

    cors: CORS (Cross-Origin Resource Sharing) เป็นกลไกที่ช่วยให้เซิร์ฟเวอร์เว็บสามารถระบุว่าต้นทาง (domain) ใดที่อนุญาตให้เข้าถึงทรัพยากรของพวกเขาได้ แพ็คเกจนี้ช่วยคุณตั้งค่า CORS ในแอปพลิเคชัน Express ของคุณ

    dotenv: Dotenv เป็นเครื่องมือที่ช่วยโหลดตัวแปรสิ่งแวดล้อม (environment variables) จากไฟล์ .env เข้าไปใน process.env ซึ่งใช้สำหรับการจัดการข้อมูลที่ลับและการกำหนดค่าในแอปพลิเคชันของคุณ

    nodemon: จะช่วยตรวจจับการเปลี่ยนแปลงในโค้ดของคุณและทำให้เซิร์ฟเวอร์ทำงานใหม่โดยอัตโนมัติเมื่อคุณบันทึกไฟล์ที่มีการเปลี่ยนแปลงเกิดขึ้น

2.  package.json เพิ่ม "type": "module" ซึ่งเป็นการระบุว่าโมดูลของโค้ดในโปรเจคนี้ใช้รูปแบบโมดูลของ ECMAScript (ES) มาตรฐาน (ES modules) ในการนำเข้าและส่งออกโค้ด คุณสมบัตินี้เป็นความสามารถของ Node.js ที่ถูกเพิ่มมาตั้งแต่เวอร์ชัน 13.2.0 ขึ้นไป (เวอร์ชัน LTS คือ 12.17.0)
    ก่อนที่จะมีคุณสมบัตินี้ โมดูลใน Node.js ใช้รูปแบบการนำเข้าและส่งออกด้วยคำสั่ง require และ module.exports แต่เมื่อใช้ "type": "module" แทน คุณสามารถใช้คำสั่ง import และ export ในการจัดการโมดูล สิ่งนี้ให้ประโยชน์ในการพัฒนาโค้ดให้เป็นไปตามมาตรฐานของ JavaScript ในเวอร์ชันล่าสุด

    เพิ่ม "scripts" : {"dev" : "nodemon index.js'}

    {
        "name": "backend",
        "version": "1.0.0",
        "description": "",
        "type": "module",
        "main": "index.js",
        "scripts": {
            "test": "echo \"Error: no test specified\" && exit 1",
            "dev": "nodemon index.js"
        },
        "keywords": [],
        "author": "",
        "license": "ISC",
        "dependencies": {
            "argon2": "^0.30.3",
            "cors": "^2.8.5",
            "dotenv": "^16.3.1",
            "express": "^4.18.2",
            "express-session": "^1.17.3",
            "mysql2": "^3.5.2",
            "nodemon": "^3.0.1",
            "sequelize": "^6.32.1"
        }
    }

3. สร้างไฟล์ index.js, สร้างไฟล์ .env

    -.env
        
        APP_PORT = 5000
        SESS_SECRET = woramettt

    -index.js
        
        โหลดค่าตัวแปรแวดล้อมจากไฟล์ .env
            
            import dotenv from 'dotenv'
            dotenv.config();

        เป็นการระบุว่าแอปพลิเคชันที่อยู่ในเว็บไซต์ที่เป็นต้นฉบับ http://localhost:3000 มีสิทธิ์ในการเรียกใช้ API ของเซิร์ฟเวอร์ของคุณ โดยค่า credentials: true ใช้กำหนดให้ส่งค่า Access-Control-Allow-Credentials: true ในการตอบกลับด้วย
            
            app.use(cors({
                credentials: true,
                origin: 'http://localhost:3000'
            }))

        เป็นการกำหนด middleware สำหรับการใช้งานเซสชัน (session) ใน Express
        session() เป็นฟังก์ชันที่ให้คุณสร้างเซสชันในแอปพลิเคชัน Express เพื่อจัดเก็บข้อมูลสถานะของผู้ใช้ระหว่างเว็บไซต์นั้นเปิดอยู่ หรือในกระบวนการทำงานของผู้ใช้ในระหว่างการเชื่อมต่อกับเซิร์ฟเวอร์ ซึ่งจะช่วยให้คุณสามารถจัดการเรื่องต่างๆ เกี่ยวกับเซสชัน เช่น การตรวจสอบการเข้าสู่ระบบของผู้ใช้ จัดการตะกร้าสินค้าในระบบออนไลน์ หรือเก็บข้อมูลการกระทำของผู้ใช้ในระยะเวลาให้ได้    
        resave: false: เป็นการกำหนดว่าต้องการเซฟเซสชันใหม่ทุกครั้งที่มีการเปลี่ยนแปลงหรือไม่ ในกรณีนี้ถ้าค่าเป็น false จะหมายความว่าเซฟเซสชันจะไม่ถูกเซฟใหม่ทุกครั้งที่มีการเปลี่ยนแปลง
        saveUninitialized: true: เป็นการกำหนดให้เซฟเซสชันที่ยังไม่มีการเซฟมาก่อน ให้ถูกเซฟในเซิร์ฟเวอร์ เมื่อมีการตั้งค่าเป็น true เซฟเซสชันจะถูกเซฟทุกครั้งที่มีการเรียกใช้งาน เพื่อให้ค่าเซฟเซสชันถูกสร้างขึ้นและเริ่มต้นก่อนการใช้งาน
        cookie: { secure: 'auto' }: เป็นการกำหนดค่าสำหรับเครื่องหมายความสำคัญ (cookie) ที่ส่งไปกับเซฟเวอร์ ในที่นี้เซฟเซสชันที่สร้างขึ้นจะส่ง cookie ที่มีค่า 'secure' เป็น 'auto' ซึ่งหมายความว่าเซิร์ฟเวอร์จะตัดสินใจเองว่าจะใช้ secure cookie หรือไม่ ซึ่ง secure cookie จะถูกส่งไปหากเป็นเว็บไซต์ที่ใช้โปรโตคอล HTTPS (เช่นเปิดใช้งาน SSL) และไม่ถูกส่งไปหากใช้โปรโตคอล HTTP
            
            app.use(session({
                secret: process.env.SESS_SECRET,
                resave: false,
                saveUninitialized: true,
                cookie: {
                    secure: 'auto'
                }
            }))


        สร้าง server
            app.listen(process.env.APP_PORT, () => {
                console.log('Server up and running')
            })

4. สร้าง folder

    backend > config > Database.js, 
    backend > controllers, 
    backend > routes,
    backend > middleware
    backend > models

5. setup database

    5.1 สร้าง Sequelize ใช้เพื่อเป็นตัวกลางในการเชื่อมต่อและจัดการกับฐานข้อมูล SQL
        
        -backend > config > Database.js 
    
        เป็นการสร้างออบเจกต์ของ Sequelize การตั้งค่า dialect: 'mysql' จะทำให้ Sequelize ใช้งานในโหมด MySQL
        การสร้างออบเจกต์ของ Sequelize ใช้เพื่อเป็นตัวกลางในการเชื่อมต่อและจัดการกับฐานข้อมูล SQL ในแอปพลิเคชันของคุณ ด้วย Sequelize คุณสามารถกำหนดโครงสร้างของตารางในฐานข้อมูล เพิ่ม ลบ แก้ไข และค้นหาข้อมูลได้สะดวกและง่ายขึ้น โดยไม่ต้องเขียนคำสั่ง SQL โดยตรง ซึ่งช่วยลดความซับซ้อนและเพิ่มความสะดวกในการจัดการฐานข้อมูลให้กับแอปพลิเคชันของคุณ

            import { Sequelize } from "sequelize";
            const db = new Sequelize('auth_db', 'root', '',{
                host: 'localhost',
                dialect: 'mysql'
            })

            export default db;

    5.2 สร้างฐานข้อมูล

        web browser > http://localhost/phpmyadmin/ > create database > database name: auth_db utf8mb4_general_ci

    5.3 กำหนดโครงสร้างตาราง, ความสัมพันธ์ตาราง

        -backend > models > UserModel.js ช่วยกำหนดโครงสร้างของตารางและความสัมพันธ์ระหว่างตารางในฐานข้อมูล

            เป็นการนำเข้า DataTypes จาก Sequelize
            DataTypes.STRING ใช้กำหนดฟิลด์ที่มีชนิดเป็นสตริง
            DataTypes.UUIDV4 ใช้กำหนดฟิลด์ที่มีชนิดเป็น UUIDv4

            uuid: เป็นชื่อฟิลด์ในตาราง users ซึ่งมีชนิดเป็นสตริง (STRING) โดยให้มีค่าเริ่มต้นเป็น UUIDv4 ด้วย
            defaultValue: DataTypes.UUIDV4 หมายความว่าถ้าไม่ระบุค่าให้กับฟิลด์นี้ Sequelize จะใช้ UUIDv4 ที่สุ่มขึ้นเป็นค่าเริ่มต้น
            allowNull: false: เป็นการกำหนดให้ฟิลด์ uuid ต้องไม่เป็นค่าว่าง (not null) คือให้เป็นข้อมูลที่มีค่าเสมอ
            validate: { notEmpty: true }: เป็นการกำหนดให้ฟิลด์ uuid ต้องมีความยาวมากกว่าศูนย์ (notEmpty) คือต้องไม่ให้เป็นสตริงว่าง (empty string)

            { freezeTableName: true }: เป็นการกำหนดให้ Sequelize ใช้ชื่อตาราง users ในฐานข้อมูลเป็นชื่อที่คุณกำหนดให้แทนที่จะใช้ชื่อเริ่มต้นที่ผิดพลาดคำจากการตั้งชื่อ Model (pluralization) โดยเฉพาะในกรณีที่มีตัวเล็ก-ใหญ่อย่างชนิดในชื่อตาราง

            import { Sequelize } from "sequelize";
            import db from '../config/Database.js'

            const {DataTypes} = Sequelize;

            const Users = db.define('users', {
                uuid:{
                    type: DataTypes.STRING,
                    defaultValue: DataTypes.UUIDV4,
                    allowNull: false,
                    validate: {notEmpty: true}
                },
                name:{
                    type: DataTypes.STRING,
                    allowNull: false,
                    validate: {notEmpty: true, len: [3, 100]}
                },
                email:{
                    type: DataTypes.STRING,
                    allowNull: false,
                    validate: {notEmpty: true, isEmail: true}
                },
                password:{
                    type: DataTypes.STRING,
                    allowNull: false,
                    validate: {notEmpty: true}
                },
                role:{
                    type: DataTypes.STRING,
                    allowNull: false,
                    validate: {notEmpty: true}
                }
            },{freezeTableName: true})

            export default Users;

        - backend > models > ProductModel.js 
            นำเข้า UsersModel เพื่อเพิ่มความสัมพันธ์
            Users.hasMany(Products) สำหรับผู้ใช้ (users) 1 คน อาจมีหลายสินค้า (products) ในระบบ
            Products.belongsTo(Users, {foreignKey: 'userId'}) หมายความว่า Model Products จำเป็นต้องมีฟิลด์ที่เป็น foreign key (userId) ที่เชื่อมโยงกับตาราง Users

            import { Sequelize } from "sequelize";
            import db from '../config/Database.js'
            import Users from './UserModel.js'

            const {DataTypes} = Sequelize;

            const Products = db.define('products', {
                uuid:{
                    type: DataTypes.STRING,
                    defaultValue: DataTypes.UUIDV4,
                    allowNull: false,
                    validate: {notEmpty: true}
                },
                name:{
                    type: DataTypes.STRING,
                    allowNull: false,
                    validate: {notEmpty: true, len: [3, 100]}
                },
                price:{
                    type: DataTypes.INTEGER,
                    allowNull: false,
                    validate: {notEmpty: true}
                },
                userId:{
                    type: DataTypes.INTEGER,
                    allowNull: false,
                    validate: {notEmpty: true}
                }
            },{freezeTableName: true})

            Users.hasMany(Products)
            Products.belongsTo(Users, {foreignKey: 'userId'})

            export default Products;
    
6. setup file controllers

    6.1 สร้าง backend > controllers > Product.js

        import Product from '../models/ProductModel.js'
        export const getProducts = (req, res) => {}
        export const getProductById = (req, res) => {}
        export const createProduct = (req, res) => {}
        export const updateProduct = (req, res) => {}
        export const deleteProduct = (req, res) => {}

    6.2 สร้าง backend > controllers > User.js

        import User from '../models/UserModel.js'
        export const getUsers = (req, res) => {}
        export const getUserById = (req, res) => {}
        export const createUser = (req, res) => {}
        export const updateUser = (req, res) => {}
        export const deleteUser = (req, res) => {}
    
7. setup file routes

    7.1 backend > routes > ProductRoute.js

        import express from 'express'
        import {getProducts, getProductById, createProduct, updateProduct, deleteProduct} from '../controllers/Product.js'

        const router = express.Router()

        router.get('/products', getProducts)
        router.get('/products/:id', getProductById)
        router.post('/products', createProduct)
        router.patch('/products/:id', updateProduct)
        router.delete('/products/:id', deleteProduct)

        export default router;

    7.2 backend > route > UserRoute.js

        import express from 'express'
        import {getUsers, getUserById, createUser, updateUser, deleteUser} from '../controllers/User.js'

        const router = express.Router()

        router.get('/users', getUsers)
        router.get('/users/:id', getUserById)
        router.post('/users', createUser)
        router.patch('/users/:id', updateUser)
        router.delete('/users/:id', deleteUser)

        export default router;

    7.3 backend > index.js

        import UserRoute from './routes/UserRoute.js'
        import ProductRoute from './routes/ProductRoute.js'
        app.use(UserRoute)
        app.use(ProductRoute)
    
8. Database sync ทำการเพิ่มค่าใน ฐานข้อมูล ด้วย code นี้ที่ไฟล์ index.js และ restart server จากนั้นเมื่อเพิ่มค่าเสร็จทำการ comment

    -index.js

        import db from './config/Database.js'

        async function asyncDB() {
            await db.sync();
        }
        
        asyncDB();

9. แก้ไข User controllers

        import User from '../models/UserModel.js'
        import argon2 from 'argon2'

        export const getUsers = async (req, res) => {
            try{
                const response = await User.findAll({
                    attributes:['uuid', 'name', 'email', 'role']
                });
                
                res.status(200).json(response)
            } catch(error){
                res.status(500).json({msg: error.message})
            }
        }

        export const getUserById = async (req, res) => {
            try{
                const response = await User.findOne({
                    attributes:['uuid', 'name', 'email', 'role'],
                    where:{
                        uuid:req.params.id
                    }
                });
                res.status(200).json(response)
            } catch(error){
                res.status(500).json({msg: error.message})
            }
        }

        export const createUser = async (req, res) => {
            const {name, email, password, confPassword, role} = req.body;
            if(password !== confPassword){
                return res.status(400).json({msg: 'Password confirm '})
            }
            const hashPassword = await argon2.hash(password)
            try{
                await User.create({
                    name: name,
                    email: email,
                    password: hashPassword,
                    role: role
                })
                res.status(201).json({msg: 'register'})
            } catch(error){
                res.status(400).json({msg: error.message})
            }
        }

        export const updateUser = async (req, res) => {
            const user = await User.findOne({
                where: {
                    uuid: req.params.id
                }
            })
            if (!user) return res.status(404).json({msg: 'User not found'})
            const {name, email, password, confPassword, role} = req.body
            let hashPassword;
            if (password === "" || password === null){
                hashPassword = user.password
            }else{
                hashPassword = await argon2.hash(password);
            }
            if(password !== confPassword){
                return res.status(400).json({msg: 'password confirm fail'})
            }
            try{
                await User.update({
                    name: name,
                    email: email,
                    password: hashPassword,
                    role: role
                }, {
                    where: {
                        id:user.id
                    }
                })
                res.status(200).json({msg: 'user update'})
            }catch(error){
                res.status(400).json({msg: error.message})
            }
        }

        export const deleteUser = async (req, res) => {
            const user = await User.findOne({
                where: {
                    uuid: req.params.id
                }
            })
            if (!user) return res.status(404).json({msg: 'Update user'})

            try{
                await User.destroy({
                    where: {
                        id:user.id
                    }
                })
                res.status(200).json({msg: 'user delete'})
            }catch(error){
                res.status(400).json({msg: error.message})
            }
        }

ิ10. ทำการ install extension > rest client

    backend > request.rest ทำการเขียน request สำหรับทดสอบ

        // Create a user
        POST http://localhost:5000/users
        Content-Type: application/json

        {
            "name": "game woramet",
            "email": "woramet1@gmail.com",
            "password": "123456",
            "confPassword": "123456",
            "role": "user"
        }

        ###
        // Get All Users
        GET http://localhost:5000/users

        ###
        // Get Single Users
        GET http://localhost:5000/users/25b76893-a9ae-4279-8541-f11384a1c90f

        ###
        // Update a Users
        PATCH http://localhost:5000/users/25b76893-a9ae-4279-8541-f11384a1c90f
        Content-Type: application/json

        {
            "name": "helloupdate",
            "email": "worametupdate@gmail.com",
            "password": "152525",
            "confPassword": "152525",
            "role": "user"
        }

        ###
        // Delete a Users
        DELETE http://localhost:5000/users/25b76893-a9ae-4279-8541-f11384a1c90f

11. setup file Auth controller

    backend > controllers > Auth.js

        import User from '../models/UserModel.js'
        import argon2 from 'argon2'

        // เมื่อมีการ login
        // การใช้ return เมื่อเรียกใช้ res เป็นสิ่งที่ควรทำ เนื่องจากมันจะช่วยป้องกันข้อผิดพลาดที่เกิดขึ้นในการทำงานของฟังก์ชัน
        // User เป็นชื่อของโมเดล (Model) ที่ใช้ในการเข้าถึงข้อมูลในฐานข้อมูลผู้ใช้ 
        // User.findOne เป็นเมธอดที่ใช้ในการค้นหาข้อมูลในฐานข้อมูลโดยใช้เงื่อนไขที่กำหนดไว้ใน where ในที่นี้คือการค้นหาผู้ใช้ที่มีอีเมลที่ตรงกับค่าใน req.body.email
        // ตรวจสอบ user password หากข้อมูลถูก return req.sessin.userId = user.uuid
        // เมื่อใช้ req.session.userId เพื่อกำหนดค่า session แล้วค่า userId จะถูกเก็บที่ server ซึ่งสามารถเข้าถึงได้ในครั้งต่อไปของ HTTP Request ที่เกิดขึ้นใน Client 
        export const Login = async(req, res) => {
            const user = await User.findOne({
                where: {
                    email: req.body.email
                }
            });
            if (!user) {
                return res.status(404).json({msg: 'User not found'})
            }
            const match = await argon2.verify(user.password, req.body.password)
            if (!match){
                return res.status(400).json({msg: 'Wrong Password'})
            }
            req.session.userId = user.uuid
            const uuid = user.uuid;
            const name = user.name;
            const email = user.email;
            const role = user.role;
            res.status(200).json({uuid, name, email, role})
        }

        
        // หากมี req.session.userId แสดงข้อมูล user นั้น
        export const Me = async(req, res) => {
            if (!req.session.userId){
                return res.status(401).json({msg: 'not found session user id'})
            }
            const user = await User.findOne({
                attributes:['uuid', 'name', 'email', 'role'],
                where:{
                    uuid: req.session.userId
                }
            })
            if (!user) {
                return res.status(404).json({msg: 'user not found'})
            }
            res.status(200).json(user)
        }

        // ทำการ req.session.destroy()
        export const Logout = (req, res) => {
            req.session.destroy((err) => {
                if(err){
                    return res.status(400).json({msg: 'err logout'})
                }
                res.status(200).json({msg: 'logout'})
            })
        }

12. setup file Auth routes

    -backend > routes > AuthRoute.js

        import express from 'express'
        import {Login, Logout, Me} from '../controllers/Auth.js'

        const router = express.Router();

        router.get('/me', Me)
        router.post('/login', Login)
        router.delete('/logout', Logout)

        export default router;
        
13. เรียกใช้งาน AuthRoute ใน index.js

    import AuthRoute from './routes/AuthRoute.js'
    app.use(AuthRoute)

14. สร้างฐานข้อมูลสำหรับเก็บ session

    backend terminal > npm i connect-session-sequelize

    -index.js เมื่อสร้างฐานข้อมูลสำหรับเก็บค่า session เสร็จ จากนั้น re-server และ comment store.sync()

        import session from 'express-session'
        import db from './config/Database.js'
        import SequelizeStore from 'connect-session-sequelize'

        const sessionStore = SequelizeStore(session.Store)
        const store = new sessionStore({
            db: db
        })

        app.use(session({
            secret: process.env.SESS_SECRET,
            resave: false,
            saveUninitialized: true,
            store: store,
            cookie: {
                secure: 'auto'
            }
        }))

        store.sync()

15. สร้าง middleware สำหรับ Auth User

    backend > middleware > MiddlewareAuthUser.js

        -MiddlewareAuthUser.js
            
            import User from '../models/UserModel.js'

            export const verifyUser = async(req, res, next) => {
                if (!req.session.userId){
                    return res.status(401).json({msg: 'middleware not found userid'})
                }
                const user = await User.findOne({
                    where: {
                        uuid: req.session.userId
                    }
                })
                if(!user){
                    return res.status(404).json({msg: 'user not found'})
                }
                req.userId = user.id;
                req.role = user.role;
                next()
            }

            export const adminOnly = async(req, res, next) => {
                const user = await User.findOne({
                    where: {
                        uuid: req.session.userId
                    }
                })
                if(!user){
                    return res.status(404).json({msg: 'user not found'})
                }
                if(user.role !== 'admin'){
                    return res.status(403).json({msg: 'not admin'})
                }
                next()
            }

        -backend > routes > UserRoute.js

            import express from 'express'
            import {getUsers, getUserById, createUser, updateUser, deleteUser} from '../controllers/User.js'
            import { verifyUser, adminOnly } from '../middleware/MiddlewareAuthUser.js'

            const router = express.Router()

            router.get('/users', verifyUser, adminOnly, getUsers)
            router.get('/users/:id', verifyUser, adminOnly, getUserById)
            router.post('/users', verifyUser, adminOnly, createUser)
            router.patch('/users/:id', verifyUser, adminOnly, updateUser)
            router.delete('/users/:id', verifyUser, adminOnly, deleteUser)

            export default router;

16. แก้ไข backend > controllers > Product.js

    -Product.js

        import Product from '../models/ProductModel.js'
        import User from '../models/UserModel.js'
        import { Op } from 'sequelize';

        // ตรวจสอบว่าเป็น admin หรือไม่ หากเป็นแสดงข้อมูล uuid name price แล้วแสดงข้อมูล name email ของตาราง user
        // ตรวจสอบว่าเป็น admin หรือไม่ หากไม่เป็นแสดงข้อมูล uuid name price ตาม product.id แล้วแสดงข้อมูล name email ของตาราง user
        export const getProducts = async(req, res) => {
            try{
                let response;
                if(req.role === 'admin'){
                    response = await Product.findAll({
                        attributes: ['uuid', 'name', 'price'],
                        include:[{
                            model: User,
                            attributes:['name', 'email']
                        }]
                    })
                }else{
                    response = await Product.findAll({
                        attributes: ['uuid', 'name', 'price'],
                        where:{
                            userId: req.userId
                        },
                        include:[{
                            model: User,
                            attributes:['name', 'email']
                        }]
                    })
                }
                res.status(200).json(response)
            }catch(error){
                res.status(500).json({msg: error.message})
            }
        }

        export const getProductById = async (req, res) => {
            try{
                const product = await Product.findOne({
                    where: {
                        uuid: req.params.id
                    }
                })
                if(!product){
                    return res.status(404).json({msg: 'Data product not found'})
                }
                let response;
                if (req.role == "admin"){
                    response = await Product.findOne({
                        attributes: ['uuid', 'name', 'price'],
                        where:{
                            id: product.id
                        },
                        include: [{
                            model: User,
                            attributes: ['name', 'email']
                        }]
                    })
                }else{
                    response = await Product.findOne({
                        attributes: ['uuid', 'name', 'price'],
                        where: {
                            [Op.and]: [{id: product.id}, {userId: req.userId}]
                        },
                        include:[{
                            model: User,
                            attributes: ['name', 'email']
                        }]
                    })
                }
                res.status(200).json(response)
            }catch(error){
                res.status(500).json({msg: error.message})
            }
        }

        export const createProduct = async (req, res) => {
            const {name, price} = req.body;
            try {
                await Product.create({
                    name: name,
                    price: price,
                    userId: req.userId
                });
                res.status(201).json({msg: "Product Created Successfuly"});
            } catch (error) {
                res.status(500).json({msg: error.message});
            }
        }
        export const updateProduct = async(req, res) => {
            try {
                const product = await Product.findOne({
                    where:{
                        uuid: req.params.id
                    }
                });
                if(!product){
                    return res.status(404).json({msg: "no product"});
                }
                const {name, price} = req.body;
                if(req.role === "admin"){
                    await Product.update({name, price},{
                        where:{
                            id: product.id
                        }
                    });
                }else{
                    if(req.userId !== product.userId){
                        return res.status(403).json({msg: "cant update this product"});
                    }
                    await Product.update({name, price},{
                        where:{
                            [Op.and]:[{id: product.id}, {userId: req.userId}]
                        }
                    });
                }
                res.status(200).json({msg: "Product updated successfuly"});
            } catch (error) {
                res.status(500).json({msg: error.message});
            }
        }

        export const deleteProduct = async(req, res) => {
        try {
                const product = await Product.findOne({
                    where:{
                        uuid: req.params.id
                    }
                });
                if(!product){
                    return res.status(404).json({msg: "no product"});
                }
                const {name, price} = req.body;
                if(req.role === "admin"){
                    await Product.destroy({
                        where:{
                            id: product.id
                        }
                    });
                }else{
                    if(req.userId !== product.userId){
                        return res.status(403).json({msg: "cant delete this product"});
                    }
                    await Product.destroy({
                        where:{
                            [Op.and]:[{id: product.id}, {userId: req.userId}]
                        }
                    });
                }
                res.status(200).json({msg: "Product deleted successfuly"});
            } catch (error) {
                res.status(500).json({msg: error.message});
            }
        }

17. เพิ่ม middleware ที่ product route

    - ProductRoute.js

        import express from 'express'
        import {getProducts, getProductById, createProduct, updateProduct, deleteProduct} from '../controllers/Product.js'
        import { verifyUser } from '../middleware/MiddlewareAuthUser.js'

        const router = express.Router()

        router.get('/products', verifyUser, getProducts)
        router.get('/products/:id', verifyUser, getProductById)
        router.post('/products', verifyUser, createProduct)
        router.patch('/products/:id', verifyUser, updateProduct)
        router.delete('/products/:id', verifyUser, deleteProduct)

        export default router;

18. ทำการเขียน request สำหรับทดสอบ Product Controller

    - backend > request.rest

        ###
        // Get All product
        GET http://localhost:5000/products

        ###
        // Get Single product
        GET http://localhost:5000/products/cbd95fa7-4acc-4623-83e4-c56dcd1a62cb

        ###
        // POST data product
        POST http://localhost:5000/products
        Content-Type: application/json

        {
            "name": "Product 1",
            "price": "991"
        }

        ###
        // POST data product
        POST http://localhost:5000/products
        Content-Type: application/json

        {
            "name": "Product 6",
            "price": "898464"
        }

        ###
        // PATCH data product
        PATCH http://localhost:5000/products/cbd95fa7-4acc-4623-83e4-c56dcd1a62cb
        Content-Type: application/json

        {
            "name": "Product update",
            "price": "12123"
        }

        ###
        // DELETE data product
        DELETE http://localhost:5000/products/cbd95fa7-4acc-4623-83e4-c56dcd1a62cb
        Content-Type: application/json

        {
            "name": "Product update",
            "price": "12123"
        }

19. ทำการติดตั้ง reactjs ในส่วน frontend

    reactjs-login-multi-role-tutorial terminal > npx create-react-app frontend --template redux
    > cd frontend
    // bulma: เป็นแพ็คเกจ CSS framework ที่มีการออกแบบและสไตล์ที่สวยงามและมีความสม่ำเสมอ ช่วยให้คุณสร้างและจัดการเลย์เอาท์ของเว็บไซต์หรือแอปพลิเคชัน React ได้อย่างรวดเร็วและสวยงาม
    > npm i react-router-dom axios bulma react-icons
    > npm start

20. setup reactjs

    frontend > src > feature > ลบ folder counter
    frontend > src > ลบ App.css, App.test.js, index.css, logo.svg, reportWebVitals.js, setupTests.js
        
    - frontend > src > index.js

        import React from 'react';
        import { createRoot } from 'react-dom/client';
        import { Provider } from 'react-redux';
        import { store } from './app/store';
        import App from './App';
        import "bulma/css/bulma.css"

        const container = document.getElementById('root');
        const root = createRoot(container);

        root.render(
        <React.StrictMode>
            <Provider store={store}>
            <App />
            </Provider>
        </React.StrictMode>
        );

    - frontend > src > App.js

        function App() {
        return (
            <div>
                Hello app
            </div>
        );
        }

        export default App;

    - frontend > src > Store.js

        import { configureStore } from '@reduxjs/toolkit';

        export const store = configureStore({
        reducer: {
            
        },
        });

21. install extension bulma snippets

22. สร้าง components (ไม่มีการ เรียก component อื่น ไว้ใช้แค่สร้าง form)

    frontend > src > components > FormAddProduct.jsx
    frontend > src > components > FormEditProduct.jsx
    frontend > src > components > FormAddUser.jsx
    frontend > src > components > FormEditUser.jsx
    frontend > src > components > Login.jsx
    frontend > src > components > Navbar.jsx
    frontend > src > components > ProductList.jsx
    frontend > src > components > Sidebar.jsx
    frontend > src > components > Userlist.jsx
    frontend > src > components > Welcome.jsx

23. สร้าง pages (มีการ เรียก component อื่น)
    
    frontend > src > pages > AddProduct.jsx
    frontend > src > pages > AddUser.jsx
    frontend > src > pages > EditProduct.jsx
    frontend > src > pages > EditUser.jsx
    frontend > src > pages > Dashboard.jsx
    frontend > src > pages > Layout.jsx
    frontend > src > pages > Product.jsx
    frontend > src > pages > Users.jsx

24. แก้ไข App.js เรียก axios, ตั้งค่าให้ Axios ส่งค่า Cookie ,พร้อมกับคำขอ สร้าง path ต่างๆ

    import { BrowserRouter, Routes, Route } from "react-router-dom";
    import Dashboard from './pages/Dashboard'
    import Login from "./components/Login";
    import Users from './pages/Users'
    import Products from "./pages/Products";
    import AddUser from "./pages/AddUser";
    import EditUser from "./pages/EditUser";
    import AddProduct from "./pages/AddProduct";
    import EditProduct from "./pages/EditProduct";
    import axios from 'axios'

    axios.defaults.withCredentials = true

    function App() {
    return (
        <div>
        <BrowserRouter>
            <Routes>
                <Route path="/"element={<Login/>} />
                <Route path="/dashboard"element={<Dashboard/>} />
                <Route path="/users"element={<Users/>} />
                <Route path="/users/add"element={<AddUser/>} />
                <Route path="/users/edit/:id"element={<EditUser/>} />
                <Route path="/products"element={<Products/>} />
                <Route path="/products/add"element={<AddProduct/>} />
                <Route path="/products/edit/:id"element={<EditProduct/>} />
            </Routes>
        </BrowserRouter>
        </div>
    );
    }

    export default App;

25. จัดการ store

    -สร้าง createSlice ใน authSlice.js
   
    //createAsyncThunk นั้นควรถูกใช้เมื่อคุณต้องการจัดการกับการทำงานแบบ Asynchronous ใน Redux Store
    //createAsyncThunk จะทำการสร้าง Action Creators แบบอัตโนมัติสำหรับสถานะการเรียกใช้งาน Async แบบ 3 สถานะคือ:
    //Pending (ระหว่างทำงาน): เมื่อคำขอถูกส่งไปทำงานแล้ว แต่ยังไม่สำเร็จ
    //Fulfilled (สำเร็จ): เมื่อการทำงาน Async สำเร็จและได้รับข้อมูลคืนมา
    //Rejected (เกิดข้อผิดพลาด): เมื่อเกิดข้อผิดพลาดในระหว่างการทำงาน Async
    //user/LoginUser คือชื่อ Action Type (action type) ของฟังก์ชัน การมี user ข้างหน้า ทำให้ง่ายต่อความเข้าใจ
    //createAsyncThunk สรุปคือเมื่อต้องการใช้เมื่อมีการทำงานแบบ Asynchronous ของ dispatch(LoginUser({email, password}))

        import {createSlice, createAsyncThunk} from '@reduxjs/toolkit'
        import axios from 'axios'

        const initialState = {
            user: null,
            isError: false,
            isSuccess: false,
            isLoading: false,
            message: ''
        }

        export const LoginUser = createAsyncThunk("user/LoginUser", async(user, thunkAPI) => {
            try{
                const response = await axios.post("http://localhost:5000/login", {
                    email: user.email,
                    password: user.password
                })
                return response.data
            } catch(error){
                if(error.response){
                    const message = error.response.data.msg
                    return thunkAPI.rejectWithValue(message)
                }
            }
        })

        export const authSlice = createSlice({
            name: 'auth',
            initialState: initialState,
            reducers: {
                reset: (state) => initialState
            },
            extraReducers:(builder) => {
                builder.addCase(LoginUser.pending, (state) => {
                    state.isLoading = true
                })
                builder.addCase(LoginUser.fulfilled, (state, action) => {
                    state.isLoading = false
                    state.isSuccess = true
                    state.user = action.payload
                })
                builder.addCase(LoginUser.rejected, (state, action) => {
                    state.isLoading = false
                    state.isError = true
                    state.message = action.payload
                })
            }
        })

        export const {reset} = authSlice.actions
        export default authSlice.reducer

    -เพิ่ม slice ใน store.js

        import { configureStore } from '@reduxjs/toolkit';
        import authReducer from '../features/authSlice'

        export const store = configureStore({
            reducer: {
                auth: authReducer
            },
        });

26. แก้ไข component Login.jsx ให้แสดงข้อผิดพลาดเมื่อรหัสผ่านผิดและเปลี่ยน path

    //useNavigete ใช้เมื่อกรณีที่ต้องการเปลี่ยนหน้าหรือนำทางโดยไม่ใช้ลิงก์ใน Element 
    //Link ควรใช้ Link ในกรณีที่ต้องการสร้างลิงก์ที่เชื่อมโยงกับ URL และต้องการส่งข้อมูลไปยัง URL นั้นๆ เช่น Query Params หรือ State

    -Login.jsx

        import React, { useState, useEffect } from "react";
        import { useDispatch, useSelector } from "react-redux";
        import { useNavigate } from "react-router-dom";
        import { LoginUser, reset } from "../features/authSlice";

        const Login = () => {
        const [email, setEmail] = useState("");
        const [password, setPassword] = useState("");
        const dispatch = useDispatch();
        const navigate = useNavigate();
        const { user, isError, isSuccess, isLoading, message } = useSelector(
            (state) => state.auth
        );

        useEffect(() => {
            if (user || isSuccess) {
            navigate("/dashboard");
            }
            dispatch(reset());
        }, [user, isSuccess, dispatch, navigate]);

        const Auth = (e) => {
            e.preventDefault();
            dispatch(LoginUser({email, password}));
        };

        return (
            <section className="hero is-fullheight is-fullwidth">
                <div className="hero-body">
                    <div className="container">
                    <div className="columns is-centered">
                        <div className="column is-4">
                        <form onSubmit={Auth} className="box">
                            {isError && <p className="has-text-centered">{message}</p>}
                            <h1 className="title is-2">Sign In</h1>
                            <div className="field">
                            <label className="label">Email</label>
                            <div className="control">
                                <input type="text" className="input" value={email} onChange={(e) => setEmail(e.target.value)} placeholder="Email"/>
                            </div>
                            </div>
                            <div className="field">
                            <label className="label">Password</label>
                            <div className="control">
                                <input type="password" className="input" value={password} onChange={(e) => setPassword(e.target.value)} placeholder="******"/>
                            </div>
                            </div>
                            <div className="field mt-5">
                            <button type="submit" className="button is-success is-fullwidth">
                                {isLoading ? "Loading..." : "Login"}
                            </button>
                            </div>
                        </form>
                        </div>
                    </div>
                    </div>
                </div>
            </section>
        );
        };

        export default Login;

27. ทำการเพิ่ม action ให้ getMe ใน authSlice.js

    -authSlice.js
        //เนื่องจาก router.get('/me', Me) มีการ return res.status(200).json(user) เมื่อมี session user id

        export const getMe = createAsyncThunk("user/getMe", async(_, thunkAPI) => {
            try{
                const response = await axios.get("http://localhost:5000/me")
                return response.data
            } catch(error){
                if(error.response){
                    const message = error.response.data.msg
                    return thunkAPI.rejectWithValue(message)
                }
            }
        })  

        export const LogOut = createAsyncThunk("user/LogOut", async(_, thunkAPI) => {
            await axios.delete("http://localhost:5000/logout")
        })

        // เพิ่ม action getMe
            builder.addCase(getMe.pending, (state) => {
                state.isLoading = true
            })
            builder.addCase(getMe.fulfilled, (state, action) => {
                state.isLoading = false
                state.isSuccess = true
                state.user = action.payload
            })
            builder.addCase(getMe.rejected, (state, action) => {
                state.isLoading = false
                state.isError = true
                state.message = action.payload
            })

28. Protected Dashboard ต้องทำการ login ก่อนเข้าสู่ระบบ

    -Dashboard.jsx 
        
        //เนื่องจาก router.get('/me', Me) มีการ return res.status(200).json(user) เมื่อมี session user id
        //เวลาเรียกใช้ dispatch(getMe()) จะมีค่าเท่ากับ dispatch(res.status(200).json(user))

        import React, {useEffect} from 'react'
        import Layout from './Layout'
        import Welcome from '../components/Welcome'
        import {useDispatch, useSelector} from 'react-redux'
        import {useNavigate} from 'react-router-dom'
        import {getMe} from '../features/authSlice'

        const Dashboard = () => {
        const dispatch = useDispatch()
        const navigate = useNavigate()
        const {isError} = useSelector((state) => state.auth)

        useEffect(() => {
            dispatch(getMe())
        }, [dispatch])

        useEffect(() => {
            if (isError){
            navigate('/')
            }
        }, [isError, navigate])

        return (
            <Layout>
                <Welcome/>
            </Layout>
        )
        }

        export default Dashboard

    -Sidebar.jsx ทำการส่ง action เมื่อมีการ logout

        import React from 'react'
        import {NavLink, useNavigate} from 'react-router-dom'
        import {IoPerson, IoPricetag, IoHome, IoLogOut} from 'react-icons/io5'
        import {useDispatch, useSelector} from "react-redux";
        import {LogOut, reset} from "../features/authSlice";

        const Sidebar = () => {
        const dispatch = useDispatch();
        const navigate = useNavigate();
        const {user} = useSelector((state) => state.auth)

        const logout = () => {
            dispatch(LogOut())
            dispatch(reset())
            navigate('/')
        }

        return (
            <div>
                <aside className="menu pl-2 has-shadow">
                    <p className="menu-label">General</p>
                    <ul className="menu-list">
                    <li>
                        <NavLink to={"/dashboard"}><IoHome/>
                        Dashboard
                        </NavLink>
                    </li>
                    <li>
                        <NavLink to={"/products"}><IoPricetag/>
                        Products
                        </NavLink>
                    </li>
                    </ul>
                    
                    <p className="menu-label">Admin</p>
                        <ul className="menu-list">
                        <li>
                            <NavLink to={"/users"}><IoPerson/>
                            Users
                            </NavLink>
                        </li>
                        </ul>

                    <p className="menu-label">Settings</p>
                    <ul className="menu-list">
                    <li>
                        <button onClick={logout} className="button is-white"><IoLogOut/>
                        Logout
                        </button>
                    </li>
                    </ul>
                </aside>
            </div>
        );
        }

        export default Sidebar

    -Navbar.jsx

        import React from 'react'
        import {NavLink, useNavigate} from 'react-router-dom'
        import logo from '../logo.jpg'
        import { useDispatch, useSelector } from "react-redux";
        import { LogOut, reset } from "../features/authSlice";

        const Navbar = () => {
        const dispatch = useDispatch();
        const navigate = useNavigate();
        const {user} = useSelector((state) => state.auth)

        const logout = () => {
            dispatch(LogOut())
            dispatch(reset())
            navigate('/')
        }

        return (
            <div>
            <nav className="navbar is-fixed-top has-shadow" role="navigation" aria-label="main navigation">
                <div className="navbar-brand">
                <NavLink to = "/dashboard" className="navbar-item">
                    <img src={logo} width="112" height="28" alt="logo"/>
                </NavLink>
            
                <a href="!#" role="button" className="navbar-burger burger" aria-label="menu" aria-expanded="false" data-target="navbarBasicExample">
                    <span aria-hidden="true"></span>
                    <span aria-hidden="true"></span>
                    <span aria-hidden="true"></span>
                </a>
                </div>
            
                <div id="navbarBasicExample" className="navbar-menu">
            
                <div className="navbar-end">
                    <div className="navbar-item">
                    <div className="buttons">
                        <button onClick={logout} className="button is-light">
                        Log out
                        </button>
                    </div>
                    </div>
                </div>
                </div>
            </nav>
            </div>
        )
        }

        export default Navbar

29. Protected หน้าต่างๆ โดย ต้องทำการ login ก่อนเข้าสู่ระบบ
        AddUser, EditUser, User ทำการตรวจสอบเช็คเงื่อนไข role เมื่อต้องการแก้ไข User โดยให้ admin แก้ไขได้เท่านั้น
        AddProduct, EditProduct, Product 

    -AddUser.jsx

        import React, {useEffect} from 'react'
        import Layout from './Layout'
        import FormAddUser from '../components/FormAddUser'
        import {useDispatch, useSelector} from 'react-redux'
        import {useNavigate} from 'react-router-dom'
        import {getMe} from '../features/authSlice'

        const AddUser = () => {
        
        const dispatch = useDispatch()
        const navigate = useNavigate()
        const {isError, user} = useSelector((state) => state.auth)

        useEffect(() => {
            dispatch(getMe())
        }, [dispatch])

        useEffect(() => {
            if (isError){
            navigate('/')
            }
            if (user && user.role !== "admin"){
            navigate("/dashboard")
            }
        }, [isError, user, navigate])

        return (
            <Layout>
                <FormAddUser/>
            </Layout>
        )
        }

        export default AddUser

    -EditUser.jsx

        import React, {useEffect} from 'react'
        import Layout from './Layout'
        import FormEditUser from '../components/FormEditUser'
        import {useDispatch, useSelector} from 'react-redux'
        import {useNavigate} from 'react-router-dom'
        import {getMe} from '../features/authSlice'


        const EditUser = () => {
        const dispatch = useDispatch()
        const navigate = useNavigate()
        const {isError, user} = useSelector((state) => state.auth)

        useEffect(() => {
            dispatch(getMe())
        }, [dispatch])

        useEffect(() => {
            if (isError){
            navigate('/')
            }
            if (user && user.role !== "admin"){
            navigate("/dashboard")
            }
        }, [isError, user, navigate])

        return (
            <Layout>
                <FormEditUser/>
            </Layout>
        )
        }

        export default EditUser

    -User.jsx

        import React, {useEffect} from 'react'
        import Layout from './Layout'
        import Userlist from '../components/Userlist'
        import {useDispatch, useSelector} from 'react-redux'
        import {useNavigate} from 'react-router-dom'
        import {getMe} from '../features/authSlice'

        const Users = () => {
        const dispatch = useDispatch()
        const navigate = useNavigate()
        const {isError, user} = useSelector((state) => state.auth)

        useEffect(() => {
            dispatch(getMe())
        }, [dispatch])

        useEffect(() => {
            if (isError){
            navigate('/')
            }
            if (user && user.role !== "admin"){
            navigate("/dashboard")
            }
        }, [isError, user, navigate])

        return (
            <Layout>
                <Userlist/>
            </Layout>
        )
        }

        export default Users

    -AddProduct.jsx

        import React, {useEffect} from 'react'
        import Layout from './Layout'
        import FormAddProduct from '../components/FormAddProduct'
        import {useDispatch, useSelector} from 'react-redux'
        import {useNavigate} from 'react-router-dom'
        import {getMe} from '../features/authSlice'

        const AddProduct = () => {

        const dispatch = useDispatch()
        const navigate = useNavigate()
        const {isError} = useSelector((state) => state.auth)

        useEffect(() => {
            dispatch(getMe())
        }, [dispatch])

        useEffect(() => {
            if (isError){
            navigate('/')
            }
        }, [isError, navigate])

        return (
            <Layout>
                <FormAddProduct/>
            </Layout>
        )
        }

        export default AddProduct
    
    -EditProduct.jsx

        import React, {useEffect} from 'react'
        import Layout from './Layout'
        import FormEditProduct from '../components/FormEditProduct'
        import {useDispatch, useSelector} from 'react-redux'
        import {useNavigate} from 'react-router-dom'
        import {getMe} from '../features/authSlice'

        const EditProduct = () => {

        const dispatch = useDispatch()
        const navigate = useNavigate()
        const {isError} = useSelector((state) => state.auth)

        useEffect(() => {
            dispatch(getMe())
        }, [dispatch])

        useEffect(() => {
            if (isError){
            navigate('/')
            }
        }, [isError, navigate])

        return (
            <Layout>
                <FormEditProduct/>
            </Layout>
        )
        }

        export default EditProduct

    -Product.jsx

        import React, {useEffect} from 'react'
        import Layout from './Layout'
        import ProductList from '../components/ProductList'
        import {useDispatch, useSelector} from 'react-redux'
        import {useNavigate} from 'react-router-dom'
        import {getMe} from '../features/authSlice'

        const Products = () => {

        const dispatch = useDispatch()
        const navigate = useNavigate()
        const {isError} = useSelector((state) => state.auth)

        useEffect(() => {
            dispatch(getMe())
        }, [dispatch])

        useEffect(() => {
            if (isError){
            navigate('/')
            }
        }, [isError, navigate])

        return (
            <Layout>
            <ProductList/>
            </Layout>
        )
        }

        export default Products

30. ทำการแสดงหรือซ่อน menu Admin ที่ sidebar เมื่อมี role = admin

    -Sidebar.jsx

        {user&&user.role === 'admin'&& (
          <div>
                    <p className="menu-label">Admin</p>
                    <ul className="menu-list">
                      <li>
                        <NavLink to={"/users"}><IoPerson/>
                           Users
                        </NavLink>
                      </li>
                    </ul>
          </div>
        )}

31. ทำการแสดงชื่อผู้ใช้เมื่อมีการ login

    -Welcome.jsx

        import React from 'react'
        import { UseSelector, useSelector } from 'react-redux'

        const Welcome = () => {
        const {user} = useSelector((state) => state.auth)
        return (
            <div>
            <h1 className="title">Dashboard</h1>
            <h2 className="subtitle">Welcome Back ...<strong>{user && user.name}</strong></h2>
            </div>
        )
        }

        export default Welcome

32. จัดการหน้า product โดยแสดงรายการ Product, ลบ product, สร้างปุ่มสำหรับ add product, edit product

    -ProductList.jsx

        import React, {useState, useEffect} from 'react'
        import {Link} from 'react-router-dom'
        import axios from 'axios'

        const ProductList = () => {
        const [products, setProduct] = useState([])

        useEffect(() => {
            getProducts()
        }, [])

        const getProducts = async () => {
            const response = await axios.get('http://localhost:5000/products')
            setProduct(response.data)
        }
        const deleteProduct = async (productId) => {
            await axios.delete(`http://localhost:5000/products/${productId}`);
            getProducts()
        }
        return (
            <div>
            <h1 className="title">Products</h1>
            <h2 className="subtitle">List of Products</h2>
            <Link to='/products/add' className='button is-primary mb-2'>Add New</Link>
            <table className="table is-striped is-fullwidth">
                <thead>
                    <tr>
                        <th>No</th>
                        <th>Product Name</th>
                        <th>Price</th>
                        <th>Create By</th>
                        <th>Actions</th>
                    </tr>
                </thead>
                <tbody>
                {products.map((product, index) => (
                    <tr key={product.uuid}>
                        <td>{index + 1}</td>
                        <td>{product.name}</td>
                        <td>{product.price}</td>
                        <td>{product.user.name}</td>
                        <td>
                        <Link to = {`/products/edit/${product.uuid}`} className = 'button is-small is-info'>Edit</Link>
                        <button onClick ={()=>deleteProduct(product.uuid)}className='button is-small is-danger'>Delete</button>
                        </td>
                    </tr>
                ))}
                </tbody>
            </table>
            </div>
        )
        }

        export default ProductList

33. Add New Product ทำการ post ข้อมูลสินค้าเมื่อมีการ submit form

    -FormAddProduct.jsx

        import React, {useState} from 'react'
        import axios from 'axios'
        import {useNavigate} from 'react-router-dom'

        const FormAddProduct = () => {
            const [name, setName] = useState('')
            const [price, setPrice] = useState('')
            const [msg, setMsg] = useState('')
            const navigate = useNavigate()

            const saveProduct = async (e) => {
                e.preventDefault();
                try{
                    await axios.post('http://localhost:5000/products', {
                        name: name,
                        price: price
                    })
                    navigate('/products')
                }catch(error){
                    if(error.response){
                        setMsg(error.response.data.msg)
                    }
                }
            }
        return (
            <div>
            <h1 className="title">Products</h1>
            <h2 className="subtitle">Add New Product</h2>
            <div className="card is-shadowless">
                <div className="card-content">
                    <div className="content">
                        <form onSubmit={saveProduct}>
                            <p className='has-text-centered'>{msg}</p>
                            <div className="field">
                                <label className="label">Name</label>
                                <div className="control">
                                    <input type="text" className='input' value={name} onChange={(e) => setName(e.target.value)} placeholder='Name' />
                                </div>
                            </div>
                            <div className="field">
                                <label className="label">Price</label>
                                <div className="control">
                                    <input type="text" className='input' value={price} onChange={(e) => setPrice(e.target.value)}placeholder='Price' />
                                </div>
                            </div>
                            <div className="field">
                                <div className="control">
                                    <button className="button is-success" type='submit'>
                                        Save
                                    </button>
                                </div>
                            </div>
                        </form>
                    </div>
                </div>
            </div>
            </div>
        )
        }

        export default FormAddProduct

34. Edit Product ทำการ patch ข้อมูลสินค้าเมื่อมีการ submit form

    -FormEditProduct.jsx ทำการนำค่า id จาก url มาแสดงจึงต้องมีการใช้ useEffect

        import React, {useState, useEffect} from 'react'
        import axios from 'axios'
        import { useNavigate, useParams } from 'react-router-dom'

        const FormEditProduct = () => {
            const [name, setName] = useState('')
            const [price, setPrice] = useState('')
            const [msg, setMsg] = useState('')
            const navigate = useNavigate()
            const {id} = useParams()

            useEffect(()=>{
                const getProductById = async () => {
                    try{
                        const response = await axios.get(`http://localhost:5000/products/${id}`)
                        console.log(response)
                        setName(response.data.name)
                        setPrice(response.data.price)
                    }catch(error){
                        if(error.response){
                            setMsg(error.response.data.msg)
                        }
                    }
                }
                getProductById()
            }, [id])

            const updateProduct = async (e) => {
                e.preventDefault();
                try{
                    await axios.patch(`http://localhost:5000/products/${id}`, {
                        name: name,
                        price: price
                    })
                    navigate('/products')
                }catch(error){
                    if(error.response){
                        setMsg(error.response.data.msg)
                    }
                }
            }
        return (
            <div>
            <h1 className="title">Products</h1>
            <h2 className="subtitle">Edit Product</h2>
            <div className="card is-shadowless">
                <div className="card-content">
                    <div className="content">
                        <form onSubmit={updateProduct}>
                            <p className='has-text-centered'>{msg}</p>
                            <div className="field">
                                <label className="label">Name</label>
                                <div className="control">
                                    <input type="text" className='input' value={name} onChange={(e) => setName(e.target.value)} placeholder='Name' />
                                </div>
                            </div>
                            <div className="field">
                                <label className="label">Price</label>
                                <div className="control">
                                    <input type="text" className='input' value={price} onChange={(e) => setPrice(e.target.value)} placeholder='Price' />
                                </div>
                            </div>
                            <div className="field">
                                <div className="control">
                                    <button className="button is-success" type='submit'>
                                        Save
                                    </button>
                                </div>
                            </div>
                        </form>
                    </div>
                </div>
            </div>
            </div>
        )
        }

        export default FormEditProduct

35. userList ทำการแก้ไข userList โดยเพิ่มปุ่ม add user, delete user มีการใช้ useEffect เพื่อดึงข้อมูล user มาแสดง

    -Userlist.jsx

        import React, {useState, useEffect} from 'react'
        import axios from 'axios'
        import {Link} from 'react-router-dom'

        const Userlist = () => {
        const [users, setUsers] = useState([])

        useEffect(() => {
            getUsers()
        }, [])

        const getUsers = async () => {
            const response = await axios.get('http://localhost:5000/users')
            setUsers(response.data)
        }
        const deleteUser = async (userId) => {
            await axios.delete(`http://localhost:5000/users/${userId}`);
            getUsers();
        }
        return (
            <div>
            <h1 className="title">Users</h1>
            <h2 className="subtitle">List of Users</h2>
            <Link to='/users/add' className='button is-primary mb-2'>Add New</Link>
            <table className="table is-striped is-fullwidth">
                <thead>
                    <tr>
                        <th>No</th>
                        <th>Name</th>
                        <th>Email</th>
                        <th>Role</th>
                        <th>Actions</th>
                    </tr>
                </thead>
                <tbody>
                {users.map((user, index) => (
                    <tr key={user.uuid}>
                        <td>{index+1}</td>
                        <td>{user.name}</td>
                        <td>{user.email}</td>
                        <td>{user.role}</td>
                        <td>
                        <Link to = {`/users/edit/${user.uuid}`} className = 'button is-small is-info'>Edit</Link>
                        <button onClick ={()=>deleteUser(user.uuid)}className='button is-small is-danger'>Delete</button>
                        </td>
                    </tr>
                ))}
                </tbody>
            </table>
            </div>
        )
        }

        export default Userlist

36. Add New User ทำการ post ข้อมูลสินค้าเมื่อมีการ submit form

    -FormAddUser.jsx

        import React, {useState} from 'react'
        import axios from 'axios'
        import {useNavigate} from 'react-router-dom'

        const FormAddUser = () => {
            const [name, setName] = useState('')
            const [email, setEmail] = useState('')
            const [password, setPassword] = useState('')
            const [confPassword, setConfPassword] = useState('')
            const [role, setRole] = useState('admin')
            const [msg, setMsg] = useState('')
            const navigate = useNavigate()

            const saveUser = async (e) => {
                e.preventDefault();
                try{
                    await axios.post('http://localhost:5000/users', {
                        name: name,
                        email: email,
                        password: password,
                        confPassword: confPassword,
                        role: role,
                    })
                    navigate('/users')
                }catch(error){
                    if(error.response){
                        setMsg(error.response.data.msg)
                    }
                }
            }

        return (
            <div>
            <h1 className="title">Users</h1>
            <h2 className="subtitle">Add New User</h2>
            <div className="card is-shadowless">
                <div className="card-content">
                    <div className="content">
                        <form onSubmit={saveUser}>
                        <p className='has-text-centered'>{msg}</p>
                        <div className="field">
                                <label className="label">Name</label>
                                <div className="control">
                                    <input type="text" className='input' value={name} onChange={(e) => setName(e.target.value)} placeholder='Name' />
                                </div>
                            </div>
                            <div className="field">
                                <label className="label">Email</label>
                                <div className="control">
                                    <input type="text" className='input' value={email} onChange={(e) => setEmail(e.target.value)} placeholder='Email' />
                                </div>
                            </div>
                            <div className="field">
                                <label className="label">Password</label>
                                <div className="control">
                                    <input type="password" className='input' value={password} onChange={(e) => setPassword(e.target.value)} placeholder='******' />
                                </div>
                            </div>
                            <div className="field">
                                <label className="label">confirm Password</label>
                                <div className="control">
                                    <input type="password" className='input' value={confPassword} onChange={(e) => setConfPassword(e.target.value)} placeholder='******' />
                                </div>
                            </div>
                            <div className="field">
                                <label className="label">Role</label>
                                <div className="control">
                                    <div className="select is-fullwidth">
                                    <select value={role} onChange={(e) => setRole(e.target.value)}>
                                            <option value="admin">Admin</option>
                                            <option value="user">User</option>
                                        </select> 
                                    </div>
                                </div>
                            </div>
                            <div className="field">
                                <div className="control">
                                    <button type='submit' className="button is-success">
                                        Save
                                    </button>
                                </div>
                            </div>
                        </form>
                    </div>
                </div>
            </div>
            </div>
        )
        }

        export default FormAddUser

37. Edit Product ทำการ patch ข้อมูล user เมื่อมีการ submit form

    -FormEditUser.jsx ทำการนำค่า id จาก url มาแสดงจึงต้องมีการใช้ useEffect

        import React, {useState, useEffect} from 'react'
        import axios from 'axios'
        import { useNavigate, useParams } from 'react-router-dom'

        const FormEditUser = () => {
            const [name, setName] = useState('')
            const [email, setEmail] = useState('')
            const [password, setPassword] = useState('')
            const [confPassword, setConfPassword] = useState('')
            const [role, setRole] = useState('admin')
            const [msg, setMsg] = useState('')
            const navigate = useNavigate()
            const {id} = useParams()

            useEffect(()=>{
                const getUserById = async () => {
                    try{
                        const response = await axios.get(`http://localhost:5000/users/${id}`)
                        setName(response.data.name)
                        setEmail(response.data.email)
                        setRole(response.data.role)
                    }catch(error){
                        if(error.response){
                            setMsg(error.response.data.msg)
                        }
                    }
                }
                getUserById()
            }, [id])

            const updateUser = async (e) => {
                e.preventDefault();
                try{
                    await axios.patch(`http://localhost:5000/users/${id}`, {
                        name: name,
                        email: email,
                        password: password,
                        confPassword: confPassword,
                        role: role,
                    })
                    navigate('/users')
                }catch(error){
                    if(error.response){
                        setMsg(error.response.data.msg)
                    }
                }
            }
        return (
            <div>
            <h1 className="title">Users</h1>
            <h2 className="subtitle">Update User</h2>
            <div className="card is-shadowless">
                <div className="card-content">
                    <div className="content">
                        <form onSubmit={updateUser}>
                            <p className='has-text-centered'>{msg}</p>
                            <div className="field">
                                <label className="label">Name</label>
                                <div className="control">
                                    <input type="text" className='input' value={name} onChange={(e) => setName(e.target.value)} placeholder='Name' />
                                </div>
                            </div>
                            <div className="field">
                                <label className="label">Email</label>
                                <div className="control">
                                    <input type="text" className='input' value={email} onChange={(e) => setEmail(e.target.value)} placeholder='Email' />
                                </div>
                            </div>
                            <div className="field">
                                <label className="label">Password</label>
                                <div className="control">
                                    <input type="password" className='input' value={password} onChange={(e) => setPassword(e.target.value)} placeholder='******' />
                                </div>
                            </div>
                            <div className="field">
                                <label className="label">confirm Password</label>
                                <div className="control">
                                    <input type="password" className='input' value={confPassword} onChange={(e) => setConfPassword(e.target.value)} placeholder='******' />
                                </div>
                            </div>
                            <div className="field">
                                <label className="label">Role</label>
                                <div className="control">
                                    <div className="select is-fullwidth">
                                    <select value={role} onChange={(e) => setRole(e.target.value)}>
                                            <option value="admin">Admin</option>
                                            <option value="user">User</option>
                                        </select> 
                                    </div>
                                </div>
                            </div>
                            <div className="field">
                                <div className="control">
                                    <button type='submit' className="button is-success">
                                        Save
                                    </button>
                                </div>
                            </div>
                        </form>
                    </div>
                </div>
            </div>
            </div>
        )
        }

        export default FormEditUser


