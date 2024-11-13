const express = require('express')
const bodyParser = require('body-parser')
const bcrypt = require('bcryptjs')
const { MongoClient, ObjectId } = require('mongodb')
const jwt = require('jsonwebtoken')
const to = require('await-to-js').default
const url = 'mongodb://localhost:27017'
const client = new MongoClient(url)
const app = express()
const dbName = 'AdvanceExpress'
require('dotenv').config()
let collection
const port = 8000
const router = express.Router()
const SECRET = process.env.SECRET_KEY
app.use(bodyParser.json())

client.connect()
.then(() => {
  console.log('connected successfully to server')
  const db = client.db(dbName)
  collection = db.collection('users')
})
.catch((error) => {
  console.log('error while connecting to server', error)
})

const authMiddleware = async (req, res, next) => {
  const authHeader = req.headers['authorization']
  const token = authHeader?.split(' ')[1]
  if (!token) {
    return res.status(401).send({
      error: 'Access Denied. No token provided.'
    })
  }
  try {
    const decoded = jwt.verify(token, SECRET)
    console.log(decoded)
  }
  catch (error) {
    console.log('err', error.name)
    const errorMessage = error.name === 'TokenExpiredError' ? 'Token has Expired' : 'Invalid Token'
    return res.status(401).send({
      error: errorMessage
    })
  }
  return next()
}

const find = async (req, res) => {
  const response = await collection.find({}).toArray()
  console.log(response)
  const filteredResponse = response.map(({password, ...rest}) => rest)
  res.status(200).send(filteredResponse)
}

const register = async (req, res) => {
  const payload = req.body
  console.log(payload)
  const existingUser  = await collection.findOne({name: payload.name})
  console.log(existingUser )
  if (existingUser ) {
    return res.status(422).send({
      error: 'userName already exists'
    })
  }
  const hashPassword = await bcrypt.hash(payload.password, 10)
  payload.password = hashPassword
  await collection.insertOne(payload)
  res.status(201).send({
    success: 'User registered successfully'
  })
}

const login = async (req, res) => {
  const {userName, password} = req.body
  const validUser = await collection.findOne({name: userName})
  if (!validUser) {
    return res.status(422).send({
      error: 'Invalid userName or password'
    })
  }
  const validPassword = await bcrypt.compare(password, validUser.password)
  if (!validPassword) {
    return res.status(422).send({
      error: 'Invalid userName or password'
    })
  }
  const options = {
    expiresIn: '1h'
  }
  delete validUser.password
  const token = jwt.sign(validUser, SECRET, options)
  validUser.token = token
  res.status(200).send(validUser)
  console.log('SECRET', SECRET)
}

const isValidObjectId = (id) => {
  return ObjectId.isValid(id)
}

const findById = async (req, res) => {
  const id = req.params.id
  if (!isValidObjectId(id)) {
    return res.status(400).send({
      error: 'Invalid Id format'
    })
  }
  const result = await collection.findOne({_id: new ObjectId(id)})
  if (!result) {
    return res.status(404).send({
      error: 'User not found'
    })
  }
  delete result.password
  res.status(200).send(result)
}

const remove = async (req, res) => {
  const id = req.params.id
  if (!isValidObjectId(id)) {
    return res.status(400).send({
      error: 'Invalid Id format'
    })
  }
  const result = await collection.deleteOne({_id: new ObjectId(id)})
  if (result.deletedCount === 1) {
    return res.status(200).send({
      success: 'User deleted successfully'
    })
  } else {
    return res.status(404).send({
      error: 'User not found'
    })
  }
}

const update = async (req, res) => {
  const id = req.params.id
  const payload = req.body
  if (!isValidObjectId(id)) {
    return res.status(400).send({
      error: 'Invalid Id format'
    })
  }
  const result = await collection.updateOne({_id: new ObjectId(id)}, {$set: payload})
  if (result.matchedCount === 0) {
    return res.status(404).send({
      error: 'User not found'
    })
  } else {
    return res.status(200).send({
      success: 'User updated successfully'
    })
  }
}

router.post('/users/register', register)
router.post('/users/login', login)
router.get('/users', authMiddleware, find)
router.get('/users/:id', authMiddleware, findById)
router.put('/users/:id', authMiddleware, update)
router.delete('/users/:id', authMiddleware, remove)
app.use('/', router)


// Handle Undefined Routes
app.use((req, res) => {
  res.status(404).send({
    error: 'endpoint not found'
  })
})

// Start Server
app.listen(port)
console.log(`The application is running on port ${port}`)
