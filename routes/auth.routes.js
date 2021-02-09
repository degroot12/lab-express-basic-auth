const router = require('express').Router();
const bcrypt = require('bcryptjs')

const UserModel = require('../models/User.model.js')

router.get('/signup', (req, res, next) => {
    res.render('auth/signup.hbs')
})

router.get('/signin', (req, res, next) => {
    res.render('auth/signin.hbs')
})

router.post('/signup', (req, res, next) => {
    const {username, password} = req.body

    if(!username || !password){
        res.render('auth/signup.hbs', {msg: 'Please enter all fields'})
        return
    }

    let salt = bcrypt.genSaltSync(10);
    hash = bcrypt.hashSync(password, salt);
    UserModel.create({username, password: hash})
        .then(() => {
            res.redirect('/signin')
        })
        .catch((err) => {
            res.render('auth/signup.hbs', {msg: 'This username is already taken'})
        })
})

router.post('/signin', (req, res, next) => {
    const {username, password} = req.body

    UserModel.findOne({username:username})
        .then((result) => {
            if(result){
                bcrypt.compare(password, result.password)
                .then((isMatching) => {
                  if(isMatching){
                    //console.log('password is correct')
                    req.session.loggedInUser = result
                    res.redirect('/main')
                  }
                  else {
                    res.render('auth/signin.hbs', {msg: 'Password does not match'})
                  }
                })
                .catch(() => {
      
                })
            } else {
                res.render('auth/signin.hbs', {msg: 'Username does not exist'})
            }
        })
        .catch((err) => {
            next(err)
        })
})


const checkLoggedInUser = (req, res, next) => {
    if(req.session.loggedInUser){
        next()
    } else {
        res.redirect('/signin')
    }
}

router.get('/main', checkLoggedInUser, (req, res) => {
    let username = req.session.loggedInUser.username
    res.render('main.hbs', {username})
})

router.get('/private', checkLoggedInUser, (req, res) => {
    let username = req.session.loggedInUser.username
    res.render('private.hbs', {username})
})


router.get('/logout',(req, res) => {
    req.session.destroy()
    res.redirect('/')
  })

module.exports = router