const express = require("express")
const app = express()
var path = require("path");
const bodyParser = require('body-parser');
var MongoClient = require('mongodb').MongoClient;
const bcrypt = require("bcrypt")
const jwt = require("jsonwebtoken")
const dotenv = require("dotenv").config()
var cookies = require("cookie-parser");

const port = 3000

app.use(express.json());
app.use(cookies());
// app.use('/public', express.static(path.join(__dirname, '/public')))
// app.use('/private', express.static(path.join(__dirname, '/private')))
app.use(express.static(path.join(__dirname, '/static')))
app.use(bodyParser.urlencoded({ extended: true }));

var url = "mongodb://localhost:27017/";

MongoClient.connect(url,(err, db)=> {
    if (err) throw err;
    let dbauth = db.db("auth");
    let collection = dbauth.collection('user')

    app.post("/register",(req,res)=>{

      const userName = req.body.name
      const userEmail = req.body.email;
      const userPassword = req.body.password;

      collection.findOne({email:userEmail}, (err, result)=> {
        if (err) throw err;
        else if(result){
          console.log(result.email);
          console.log('Email already exists');
          res.send({error:"Email already exist"})
        }
        else{
          jwt.sign({email:userEmail}, process.env.TOKEN_SECRET,(err,token)=>{
            if(err){
              res.send({error:"Authentication failed"})
            }
            else{
              bcrypt.hash(userPassword,8).then(hashedPassword=>{
                const user = {
                  name:userName,
                  email:userEmail,
                  password:hashedPassword,
                  tokens:[token]
                }
                collection.insertOne(user,(err,results)=>{
                  if (err) throw err;
                  else if(results){
                    console.log("User Added Successfully")
                    res.send({result:"User Added Successfully",
                      token
                    })
                  }            
                })
              })
            }
          })
        }
      })
    })

    app.post("/login",(req,res)=>{

        const userEmail = req.body.email;
        const userPassword = req.body.password;

        collection.findOne({email:userEmail},(err, result)=> {
            if (err) throw err;
            if(result){
              console.log(result.email);
              console.log({error:'Email exists in database'});
              
              const dbPassword = result.password
              const tokens = result.tokens

              bcrypt.compare(userPassword, dbPassword).then(isMatch=>{
                if(isMatch){
                  jwt.sign({email:userEmail}, process.env.TOKEN_SECRET,(err,token)=>{
                    if(err){
                      res.send({error:"Error! Authentication failed"})
                    }
                    else{
                      let newtokensarray = [...tokens,token]
                      collection.updateOne({email:userEmail},{$set:{tokens:newtokensarray}}).then(response=>{
                        console.log(response)
                        console.log("User Authorized")
                        res.send({result:"User Authorized",token,userEmail})
                      }).catch(e=>{
                        res.send(e)
                      })                     
                    }
                  })         
                }
                else{
                  console.log("Invalid password")
                  res.send({error:"Invalid password"})
               }
              })             
            }
            else{
              console.log('Invalid Email Id');
              res.send({error:"Invalid Email Id"})
            }
          });    
    })

    app.get('/',verifyToken,(req,res)=>{ 

      res.sendFile(path.join(__dirname, '/static/private/private.html'))
    
    })
    
    function verifyToken(req,res,next){
      let auth_token = req.cookies.Authorization      

      if(auth_token){
        jwt.verify(auth_token,  process.env.TOKEN_SECRET, function(err, decoded) {
        collection.findOne({email:decoded.email}).then(result=>{

          result.tokens.forEach(element => {
            if(element==auth_token){
              next()
            }
          });

          res.sendFile(path.join(__dirname, '/static/public/login.html'))
        })
        .catch(e=>{
          res.sendFile(path.join(__dirname, '/static/public/login.html'))
        })
      })  
    }
    else{
      res.sendFile(path.join(__dirname, '/static/public/login.html'))
    }      
    }
})


app.listen(port,function(){
    console.log("app is listening on port 3000...")
})