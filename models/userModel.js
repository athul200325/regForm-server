const mongoose=require('mongoose')

const User=new mongoose.Schema({
    username: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    phone: { type: String, required: true},
    password: { type: String, required: true },
}
)

const model = mongoose.model('UserData',User)

module.exports=model