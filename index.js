const express = require('express');
const path = require('path');
const mongoose = require("mongoose");
const cookieParser = require('cookie-parser');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const { config } = require("dotenv")

config({
    path: "./config.env"
});

mongoose.connect(process.env.MONGO_URI, {
    dbName: "backend",
})
.then(()=>{
    console.log("DATABSE CONNECTION SUCCESSFULLY ESTABLISHED")
})
.catch((e)=>{
    console.log(e);
})

const msgSchema = new mongoose.Schema({
    email: {
        type: String,
        required: true
    },
    message: {
        type: String,
        required: true
    },
});

const Message = mongoose.model("Message", msgSchema);

const userSchema = new mongoose.Schema({
    username: {
        type: String,
        required: true
    },
    fullname: {
        type: String,
        required: true
    },
    email: {
        type: String,
        required: true
    },
    password: {
        type: String,
        required: true
    }
})

const User = mongoose.model("User", userSchema)

const app = express();

//Using middleware
app.use(express.static(path.join(path.resolve(), "public")));
app.use(express.urlencoded({ extended: true }))
app.use(cookieParser())

// Setting up view engine
app.set("view engine", "ejs")

// Middleware function
const isAuth = async(req, res, next) =>{
    const { token } = req.cookies;
    if(token){
        const decoded = jwt.decode(token, process.env.JWT_SECRET);
        req.user = await User.findById(decoded._id);
    }
    next();
}

// auth functions
const encryptPassword = async(password) =>{
    const saltRounds = 10;
    const encryptedPass = await bcrypt.hash(password, saltRounds);
    return encryptedPass
}

const decryptPassword = async(userpassword, dbpassword) =>{
    const isSame = bcrypt.compare(userpassword, dbpassword);
    return isSame;
}



app.get('/', isAuth,(req, res) => {
    if(req.user){
        res.render('index')
    }else{
        res.render('login')
    }
})

app.get('/login', isAuth,(req, res)=>{
    if(req.user){
        res.redirect('/');
    }else{
        res.render('login');
    }
})


app.get('/contact', (req, res)=>{
    res.render('contact');
})

app.post('/login', async (req, res)=>{
    const { username, password } = req.body;
    const user = await User.findOne({ username });
    if(!user){
        return res.render('login', { message: "Incorrect username or password!"})
    }
    const isCorrect = await decryptPassword(password, user.password)
    if(!isCorrect){
        return res.render('login', { message: "Incorrect username or password!"})
    }

    const token = jwt.sign({
        _id: user._id
    }, process.env.JWT_SECRET)
    res.cookie("token", token, {
        httpOnly: true,
        expires: new Date(Date.now() + 15 * 24 * 60 * 60 * 1000)
    })
    res.redirect('/')
})

app.get('/logout', (req, res)=>{
    res.cookie("token", null, {
        httpOnly: true,
        expires: new Date(Date.now())
    })
    res.redirect('/')
})

app.get('/signup', isAuth, (req, res)=>{
    if(req.user){
        res.redirect('/');
    }
    else{
        res.render('signup');
    }
})

app.post('/signup', async(req, res)=>{
    const { username, fullname, email, password } = req.body;

    const user = await User.findOne({ username });

    if(user){
        return res.send("A user with this username already exists!")
    }

    const hashedPassword = await encryptPassword(password)

    const newUser = await User.create({
        username, fullname, email, password: hashedPassword
    })

    const token = jwt.sign({
        _id: newUser._id
    }, process.env.JWT_SECRET);
    res.cookie("token", token, {
        httpOnly: true,
        expires: new Date(Date.now() + 15 * 24 * 60 * 60 * 1000)
    })
    res.redirect('/')
})



app.get('/fail',(req, res)=>{
    res.render('status',{ stat: "FAILED!" });
})

app.get('/success',(req, res)=>{
    res.render('status',{ stat: "SUCCESS!" });
})

app.post('/sendmessage', async(req, res)=>{
    const { email, message } = req.body
    if(email.length === 0 || message.length === 0){
        return res.redirect("/fail");
    }
    await Message.create({email, message})
    res.redirect("/success");
})

app.listen(process.env.PORT,()=>{
    console.log('SERVER ESTABLISHED SUCCESSFULLY!')
})