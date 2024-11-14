const express = require('express');
const bcrypt = require('bcrypt');
const cors = require('cors');
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const User = require("./models/userModel");
const userRoutes = require('./userName');
require('dotenv').config();

const app = express();

app.use(cors());
app.use(express.json()); 

mongoose.connect('mongodb://localhost:27017/login-reg-form')
    .then(()=>console.log('MongoDB connected successfully'))
    .catch(err=>console.error('MongoDB connection error:', err));

app.use('/api',userRoutes);

app.post('/api/reg',async(req,res)=>{
    try{
        const{username,email,phone,password}=req.body;

        const existingUser=await User.findOne({email});
        if(existingUser){
            return res.status(400).json({status:'error',error:'Duplicate email'})
        }

        const hashedPassword=await bcrypt.hash(password,10);

        const newUser=new User({username,email,phone,password:hashedPassword});
        await newUser.save();

        res.json({status:'ok'});

    }catch(err){
        console.error(err);
        res.status(500).json({status:'error',error:'An unexpected error occurred'});
    }
});

app.post('/api/login',async (req,res)=>{
    const {email,password}=req.body;

    try{
        const user=await User.findOne({email});
        if(!user){
            return res.status(404).json({status:'error',error:'User not found'});
        }

        const isPasswordValid=await bcrypt.compare(password,user.password);
        if (!isPasswordValid){
            return res.status(401).json({status:'error',error:'Invalid password'});
        }

        const token=jwt.sign({username:user.username,email:user.email,phone:user.phone},process.env.JWT_SECRET,{expiresIn:'1h'});
        res.json({status:'ok',user:token });

    }catch(err){
        console.error(err);
        res.status(500).json({status:'error',error:'An unexpected error occurred'});
    }
});

app.listen(3000,()=>{
    console.log('Server running on port 3000');
});
