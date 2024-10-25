const mongoose = require("mongoose");

const userSchema = new mongoose.Schema(
    {
        name:{
            type:String,
            required: true,
        },
        email:{
            type:String,
            required: true,
        },
        password:{
            type:String,
            required: true,
        },
        department:{
            type:String,
            required: true,
        },
        level:{
            type:String,
            required: true,
        },

    
    }, {timestamps:true});
    module.exports = mongoose.model("User", userSchema);