const express = require('express');
const jwt = require('jsonwebtoken');
const User = require('./models/userModel');
const router = express.Router();

const authenticateJWT= (req,res,next)=>{
    const token= req.header('x-access-token');
    if(!token){
        return res.status(401).json({status:'error',error:'Access denied. No token provided'});
    }

    jwt.verify(token,process.env.JWT_SECRET,(err,user)=>{
        if(err){
            return res.status(403).json({status:'error',error:'Token is not valid'});
        }
        req.user=user; 
        next();
    });
}

router.get('/user',authenticateJWT,async(req,res)=>{
    try{
        const user=await User.findOne({email:req.user.email});
        if(!user){
            return res.status(404).json({status:'error',error:'User not found'});
        }

        res.json({
            username:user.username,
            email:user.email,
            phone:user.phone
        });
    }catch(err){
        console.error(err);
        res.status(500).json({status:'error',error:'Server error.'});
    }
});

module.exports= router;
