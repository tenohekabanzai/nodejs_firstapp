const express  = require("express");
const app  = express();
const path = require("path");
const mongoose = require("mongoose");
const cookieParser = require("cookie-parser");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");

mongoose.connect("mongodb://127.0.0.1:27017/",{
    dbName:"backend"
}).then(console.log("Connected to MongoDB")).catch(err=>console.log(err));


const x = new mongoose.Schema({
    name:String,
    email:String,
    password: String,
})

const u = new mongoose.model("User",x);

// Using MiddleWares
app.use(express.static(path.join(path.resolve(),"public")));
app.use(express.urlencoded({extended: true}));
app.use(cookieParser());

// setting up view Engine
app.set("view engine","ejs");

// Middleware
const isAuthenticated = async(req,res,next)=>{
    const token  = req.cookies.token;
    if(token)
    {
        const decoded = jwt.verify(token,"12345");
        req.user = await u.findById(decoded._id);
        next();
    }
    else
    res.redirect("/login");

}

app.get("/",isAuthenticated,(req,res)=>{
    res.render("logout",{name:req.user.name});
})

app.get("/register",(req,res)=>{
    res.render("register");
})
app.get("/login",(req,res)=>{
    res.render("login");
})

app.post("/login",async(req,res)=>{
    const { email,password} = req.body;
    let x = await u.findOne({email});
    if(!x)
    return res.redirect("/register");

    const match = bcrypt.compare(password,x.password);
    
    if(!match)
    return res.render("login", { email, message: "Incorrect Password" });

    const token = jwt.sign({_id:x._id},"12345");
    res.cookie("token",token,{
        httpOnly: true,
        expires: new Date(Date.now() + 60*1000)
    });
    res.redirect("/");
})

app.post("/register",async(req,res)=>{

    const { name,email,password } = req.body;
    const h = await bcrypt.hash(password,10);
    let p = await u.findOne({email});
    if(p)
    return res.redirect("/login");    

    const x = await u.create({name,email,password:h})
    const token = jwt.sign({_id:x._id},"12345");
    res.cookie("token",token,{
        httpOnly: true,
        expires: new Date(Date.now() + 60*1000)
    });
    res.redirect("/");
})

app.get("/logout",(req,res)=>{
    res.cookie("token",null,{
        httpOnly: true,
        expires: new Date(Date.now())
    });
    res.redirect("/");
})



app.listen(5000,(req,res)=>{
    console.log("Server is up and running at http://localhost:5000/");
})