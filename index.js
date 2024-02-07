import express from "express"
import dotenv from "dotenv"
import mongoose from "mongoose"
import cors from 'cors'
import cookieParser from "cookie-parser"
dotenv.config()
import { UserRouter } from "./routes/user.js"

const app = express()
app.use(express.json())
app.use(cors(
    {
        origin:["http://localhost:5173"],
        credentials:true
    }
))
app.use(cookieParser())
app.use('/auth',UserRouter)

mongoose.connect('mongodb+srv://prahladgaur0711:Prahlad0711@cluster0.rzcxx5t.mongodb.net/authentication')

app.listen(process.env.PORT,()=>{
    console.log("server is running")
})