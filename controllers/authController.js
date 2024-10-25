const User = require("../models/User");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const register = async (req,res)=>{
    const {name,email,password,department,level} = req.body;
    if(!name || !email || !password || !department || !level){
        return res.status(400).json({ message: "All fields are required"});
    }

    if (!email.endsWith("@ci.suez.edu.eg")) {
        return res.status(400).json({ message: "Invalid email domain" });
      }
      
    const foundUser = await User.findOne({email}).exec();
    if(foundUser){
        return res.status(401).json({ message: "User already exists"});
    }
    const hashedPassword = await bcrypt.hash(password,10)

    const user = await User.create({
        name,
        email,
        password: hashedPassword,
        department,
        level,
    });

    const accessToken = jwt.sign({
        UserInfo:{
            id:user._id,
        },
    }, 
    process.env.ACCESS_TOKEN_SECRET , 
    {expiresIn:"15m"}
  );
    const refreshToken = jwt.sign(
        {
            UserInfo:{
              id:user._id,
    },
}, 
    process.env.REFRESH_TOKEN_SECRET,
    {expiresIn:"60d"}

  );
  res.cookie("jwt",refreshToken, {
    httpOnly:true,
    secure: true,
    sameSite: "None",
    maxAge : 7 * 24 * 60 * 60 * 1000
  });
  res.json({
    accessToken, 
    email:user.email,
    name:user.name,
    department: user.department,
    level: user.level
});



};
const login = async (req,res)=>{
    const {email,password} = req.body;
    if(!email || !password ){
        return res.status(400).json({ message: "All fields are required"});
    }
    const foundUser = await User.findOne({email}).exec();
    if(!foundUser){
        return res.status(401).json({ message: "User does not exist"});
    }
    const match = await bcrypt.compare(password, foundUser.password);

    if (!match) return res.status(401).json({ message:"Wrong Password"});

   

    const accessToken = jwt.sign({
        UserInfo:{
            id:foundUser._id,
        },
    }, 
    process.env.ACCESS_TOKEN_SECRET , 
    {expiresIn:"15m"}
  );
    const refreshToken = jwt.sign(
        {
            UserInfo:{
              id:foundUser._id,
    },
}, 
    process.env.REFRESH_TOKEN_SECRET,
    {expiresIn:"60d"}

  );
  res.cookie("jwt",refreshToken, {
    httpOnly:true,
    secure: true,
    sameSite: "None",
    maxAge : 7 * 24 * 60 * 60 * 1000
  });
  res.json({
    accessToken, 
    email:foundUser.email,
    
});



};
const refresh = (req,res)=>{
    const cookies = req.cookies;
    if(!cookies?.jwt) res.status(401).json({ message: "Unauthorized" });
    const refreshToken = cookies.jwt
    jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET , async(err,decoded)=>{
        if(err) return res.status(403).json({ message: "Forbidden" });
        const foundUser = await User.findById(decoded.UserInfo.id).exec();
        if(!foundUser) return res.status(401).json({ message: "Unauthorized" });
        const accessToken = jwt.sign({
            UserInfo:{
                id:foundUser._id,
            },
        }, 
        process.env.ACCESS_TOKEN_SECRET , 
        {expiresIn:"15m"}
      );
      res.json({ accessToken });
 
    }
 );


};
const logout = (req,res)=>{
    const cookies = req.cookies;
    if(!cookies?.jwt) return res.sendStatus(204);
    res.clearCookie("jwt", {
        httpOnly: true,
        sameSite: "None",
        secure: true,
    });
    res.json({ message: "Cookie cleared"});

};
module.exports = {
    register,
    login,
    refresh,
    logout,
};