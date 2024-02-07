import express from 'express'
import bcrypt from 'bcrypt'
const router = express.Router();
import { User } from '../models/User.js';
import jwt from 'jsonwebtoken';
import nodemailer from 'nodemailer';


//Sign Up Route   
router.post('/signup', async (req, res)=>{
    const {username, email, password} = req.body;
    const user = await User.findOne({email})
    if(user){
        return res.json({message:"user already existed"})
    }

    const hashedPassword = await bcrypt.hash(password,10)
    const newUser = new User({
        username,
        email,
        password:hashedPassword
        
    })
    await newUser.save()
    return res.json({status:true, message:"record registered"})

})


//Login Route
router.post('/login', async (req,res)=>{
    const{email, password} = req.body;
    const user = await User.findOne({email})
    if(!user){
        return res.json({message:"user is not registered"})
    }
    const validPassword = await bcrypt.compare(password,user.password)
    if(!validPassword){
        return res.json({message:"password is incorrect"})
    }
    const token = jwt.sign({username:user.username}, process.env.KEY, {expiresIn:'1h'})
    res.cookie('token',token,{httpOnly:true, maxAge:360000})
    return res.json({status:true, message:"login successfully"})

})

//Forgot-Password Route
router.post('/forgot-password',async (req,res)=>{
    //to check registered email
    const {email} = req.body;
    try{
     const user = await User.findOne({email}) 
     if(!user){
        return res.json({message:"User not registered"})
     }  
     
     const token = jwt.sign({id: user._id}, process.env.KEY, {expiresIn:'5m'})
     var transporter = nodemailer.createTransport({
        service: 'gmail',
        auth: {
          user: 'gaurprahlad776@gmail.com',
          pass: 'Prahlad@0711'
        }
      });
      
      var mailOptions = {
        from: 'gaurprahlad776@gmail.com',
        to: email,
        subject: 'Reset Password',
        text: `http://localhost:5173/resetPassword/${token}`
      };
      
      transporter.sendMail(mailOptions, function(error, info){
        if (error) {
            return res.json({message:"Error sending email"})
        } else {
            return res.json({status:true,message:"email sent"})
        }
      });
    }catch(err){
        console.log(err)
    }
})

// For Logout
router.get('/logout', (req, res)=>{
    res.clearCookie('token')
    return res.json({status:true})
})

export {router as UserRouter}