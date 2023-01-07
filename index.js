const express = require('express')
const app = express()
const mongodb = require('mongodb')
const mongoclient = mongodb.MongoClient;
const dotenv = require("dotenv").config()
const URL = process.env.DB
const bcrypt = require("bcrypt")
const jwt = require("jsonwebtoken")
const nodemailer = require("nodemailer");
const crypto = require("crypto")
const JWT_SC = process.env.secret_key
const cors = require('cors')

app.use(express.json())
app.use(cors())
const transport = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.email,
        pass: process.env.password
    }
})
let currentokenNumber = 0
function generatetoken() {
    currentokenNumber++
    return `Token-${Math.floor(Math.random() * 10000).toString().padStart(4, '0')}-${currentokenNumber}`;
}

app.post('/place-order/:userId', async (req, res) => {
    try {
        const connection = await mongoclient.connect(URL)
        const db = connection.db("foodtoken")
        const user = await db.collection("users").findOne({ _id: mongodb.ObjectId(req.params.userId) })
        if(user){
            const token = generatetoken()
            res.json({message:`Your order has been placed, your token is ${token}`})
            await db.collection("users").updateOne({_id:mongodb.ObjectId(req.params.userId)},{ $set: {order : {foodtoken : token, orderdata : req.body}} })
        }
    } catch (error) {
        console.log(error)
    }

})

app.post('/user/register', async (req, res) => {
    try {
        const connection = await mongoclient.connect(URL)
        const db = connection.db("foodtoken")
        const salt = await bcrypt.genSalt(10)
        const hash = await bcrypt.hash(req.body.password, salt)
        req.body.password = hash
        await db.collection("users").insertOne(req.body)
        await connection.close()
        res.json({ message: "User created" })
    } catch (error) {
        console.log(error)
    }
})

app.post("/user/login", async (req, res) => {
    try {
        const connection = await mongoclient.connect(URL);
        const db = await connection.db("foodtoken")
        const user = await db.collection("users").findOne({ email: req.body.email })
        if (user) {
            const passwordcheck = await bcrypt.compare(req.body.password, user.password)
            if (passwordcheck) {
                const token = jwt.sign({ _id: user._id }, JWT_SC, { expiresIn: "2m" })
                res.json({ message: "Success", token, id: user._id })
            } else {
                res.json({ message: "Incorrect email/password" })
            }
        } else {
            res.status(404).json({ message: "Incorrect email/password" })
        }
    } catch (error) {
        console.log(error)
    }
})

app.post('/user/forgotpassword', async function (req, res, next) {
    try {
        const connection = await mongoclient.connect(URL);
        const db = connection.db("foodtoken")
        const user = await db.collection("users").findOne({ email: req.body.email });
        if (user) {
            const resettoken = crypto.randomBytes(16).toString('hex');
            await db.collection("users").updateOne({ _id: user._id }, { $set: { token: resettoken } })
            const mailOptions = {
                from: "d73330670@gmail.com",
                to: user.email,
                subject: "Reset your password",
                html: `<p>Click <a href="http://localhost:3000/reset-password?token=${resettoken}">here</a> to reset your password.</p>`
            }
            await connection.close()
            res.json({ message: "Email sent", token: resettoken })
            transport.sendMail(mailOptions, (error, info) => {
                if (error) {
                    console.log(error)
                } else {
                    console.log(`Email sent: ${info.response}`)
                }
            })
        } else {
            res.json({ message: "Email address not valid" })
        }
    } catch (error) {
        console.log(error)
    }
})

app.get('/reset-password', async (req, res) => {
    try {
        const token = req.query.token
        const connection = await mongoclient.connect(URL);
        const db = connection.db("foodtoken")
        const validtoken = await db.collection("users").findOne({ token: token });
        if (validtoken) {
            res.redirect(`http://localhost:3001/reset-password-page?token=${token}`);
        }
        else {
            console.log("Token invalid")
        }
    } catch (error) {
        console.log(error)
    }
})

app.post('/reset-password-page', async (req, res) => {
    try {
        const token = req.query.token
        const connection = await mongoclient.connect(URL);
        const db = connection.db("foodtoken")
        const validtoken = await db.collection("users").findOne({ token: token });
        if (validtoken) {
            const salt = await bcrypt.genSalt(10)
            const hash = await bcrypt.hash(req.body.password, salt)
            req.body.password = hash
            await db.collection("users").updateOne({ token: token }, { $set: { password: req.body.password } })
            await connection.close()
            res.json({ message: "Password has been reset" })
        }
    } catch (error) {
        console.log(error)
    }
})

app.get("/user/:userId", async (req, res) => {
    try {
      const connection = await mongoclient.connect(URL);
      const db = connection.db("foodtoken");
      const user = await db.collection("users").find({ _id: mongodb.ObjectId(req.params.userId) }).toArray();
      await connection.close();
      res.json(user);
      console.log(user)
    } catch (error) {
      res.status(500).json({ message: "Something went wrong for get user" });
    }
  });

app.listen(3000, () => { console.log("App running on port 3000") })