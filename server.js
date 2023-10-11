import express, { Router } from "express"
import mysql from "mysql2"
import cors from "cors"
import jwt from "jsonwebtoken"
import bcrypt from "bcrypt"
import cookieParser from "cookie-parser"

const PORT = 3000
const app = express()
app.use(express.json())
app.use(
  cors({
    origin: "http://localhost:5173",
    methods: ["POST", "GET", "DELETE", "PUT"],
    credentials: true,
  })
)
app.use(cookieParser())

const db = mysql.createConnection({
  host: "localhost",
  user: "root",
  password: "",
  database: "contact_db",
})

const users = []

app.post("/signup", (req, res) => {
  const sql =
    "INSERT INTO `user` (`username`, `first_name`, `last_name`, `address`, `password`) VALUES (?, ?, ?, ?, ?)"
  bcrypt.hash(req.body.password, 10, (err, hash) => {
    const values = [
      req.body.username,
      req.body.first_name,
      req.body.last_name,
      req.body.address,
      hash,
    ]
    db.query(sql, values, (err, result) => {
      // if(err ===)
      if (err) {
        res.status(400).json(err)
      }
      if (result) {
        res.status(201).json({ message: "User inserted successfully" })
      }
    })
  })
})

app.post("/login", (req, res) => {
  const sql = "SELECT * FROM `user` WHERE username = ?"

  db.query(sql, [req.body.username], (err, data) => {
    if (err) return res.status(500).send("Error")
    if (data.length > 0) {
      bcrypt.compare(req.body.password, data[0].password, (err, match) => {
        const { id, username, first_name, last_name, address } = data[0]
        console.log(match)
        if (match) {
          const tokenInfo = {
            id,
            username,
            first_name,
            last_name,
            address,
          }
          const userInfo = {
            id,
            username,
            first_name,
            last_name,
            address,
          }
          const token = jwt.sign({ tokenInfo }, "secret", {
            expiresIn: "1d",
          })

          // Set the 'token' cookie
          res.cookie("token", token, { httpOnly: true })

          return res.json(userInfo)
        } else {
          return res.status(400).json({ error: "Wrong password" })
        }
      })
    } else {
      return res.status(400).json({ error: "No user found" })
    }
  })
})

app.delete("/logout", (req, res) => {
  res.clearCookie("token")
  return res.json({ status: "success" })
})

app.get("/me", verifyUser, (req, res, next) => {
  const { username } = req.tokenInfo
  const sql = "SELECT * FROM `user` WHERE username = ?"

  db.query(sql, [username], (err, data) => {
    if (data) {
      const { username, first_name, last_name, address } = data[0]
      const userInfo = {
        username,
        first_name,
        last_name,
        address,
      }
      return res.json(userInfo)
    }

    if (err) {
      return res.json(err)
    }
  })
})

function verifyUser(req, res, next) {
  const token = req.cookies.token
  if (!token) {
    return res.status(400).json({ error: "Not authenticated" })
  } else {
    jwt.verify(token, "secret", (err, decoded) => {
      if (err) {
        return res.status(400).json({ error: "Not authenticated" })
      } else {
        req.tokenInfo = decoded.tokenInfo
        next()
      }
    })
  }
}

app.get("/contact/:id", verifyUser, (req, res) => {
  const contactId = req.params.id
  const userId = req.tokenInfo.id
  console.log(contactId, userId)
  const sql = "SELECT * FROM `contact` WHERE userId = ? AND id = ?"
  db.query(sql, [userId, contactId], (err, results) => {
    if (err) {
      return res.json(err)
    } else {
      return res.json(results[0])
    }
  })
})

app.get("/contact", verifyUser, (req, res) => {
  const id = req.tokenInfo.id
  const sql =
    "SELECT * FROM `contact` WHERE userId = ? ORDER BY `createdAt` DESC"
  db.query(sql, [id], (err, results) => {
    if (err) {
      return res.json(err)
    } else {
      return res.json(results)
    }
  })
})

app.post("/contact", verifyUser, (req, res) => {
  const { first_name, last_name, email, phone, address } = req.body
  const sql =
    "INSERT INTO `contact` (`userId`, `first_name`, `last_name`, `email`, `phone`, `address`) VALUES (?, ?, ?, ?, ?, ?)"
  const values = [
    req.tokenInfo.id,
    first_name,
    last_name,
    email,
    phone,
    address,
  ]
  db.query(sql, values, (err, results) => {
    if (err) {
      return res.status(400).json(err)
    } else {
      return res.json(results)
    }
  })
})

app.delete("/contact/:id", verifyUser, (req, res) => {
  const id = req.params.id
  const userId = req.tokenInfo.id
  const sql = "DELETE FROM contact WHERE id = ? AND userId = ?"
  db.query(sql, [id, userId], (err, results) => {
    if (err) {
      return res.json(err)
    } else {
      return res.json(results)
    }
  })
})

app.put("/contact/:id", verifyUser, (req, res) => {
  const contactId = req.params.id
  const userId = req.tokenInfo.id
  const { first_name, last_name, email, phone, address } = req.body

  // Check if the user provided any update data
  if (!first_name && !last_name && !email && !phone && !address) {
    return res.status(400).json({ error: "No update data provided" })
  }

  // Construct the SQL UPDATE query dynamically based on provided fields
  const updateFields = []
  const updateValues = []

  if (first_name) {
    updateFields.push("first_name = ?")
    updateValues.push(first_name)
  }

  if (last_name) {
    updateFields.push("last_name = ?")
    updateValues.push(last_name)
  }

  if (email) {
    updateFields.push("email = ?")
    updateValues.push(email)
  }

  if (phone) {
    updateFields.push("phone = ?")
    updateValues.push(phone)
  }

  if (address) {
    updateFields.push("address = ?")
    updateValues.push(address)
  }

  updateValues.push(contactId) // Add the contactId to the end of values array

  // Update the contact only if it belongs to the authenticated user
  const sql = `UPDATE contact SET ${updateFields.join(
    ", "
  )} WHERE id = ? AND userId = ?`

  // Execute the update query
  db.query(sql, [...updateValues, userId], (err, results) => {
    if (err) {
      return res.status(400).json(err)
    } else if (results.affectedRows === 0) {
      return res
        .status(404)
        .json({ error: "Contact not found or does not belong to the user" })
    } else {
      return res.json({ message: "Contact updated successfully" })
    }
  })
})

app.put("/user", verifyUser, (req, res) => {
  const { id } = req.tokenInfo
  const { first_name, last_name, address, username } = req.body
  const sql =
    "UPDATE `user` SET `first_name` = ?, `last_name` = ?, `address` = ?, `username` = ? WHERE `user`.`id` = ?"
  const values = [first_name, last_name, address, username, id]
  db.query(sql, values, (err, results) => {
    if (err) {
      return res.status(400).json(err)
    } else {
      return res.json(results)
    }
  })
})

app.get("/search/:key", verifyUser, (req, res) => {
  const { id } = req.tokenInfo
  const { key } = req.params
  const searchTerm = `%${key}%`

  const sql = `
  SELECT *
  FROM contact
  WHERE (first_name LIKE ? OR last_name LIKE ? OR SUBSTRING_INDEX(email, '@', 1) LIKE ?) AND userId = ?
`

  db.query(sql, [searchTerm, searchTerm, searchTerm, id], (err, results) => {
    if (err) {
      return res
        .status(500)
        .json({ error: "An error occurred while searching." })
    }
    return res.status(200).json(results)
  })
})

app.listen(PORT, () => console.log("Running on port", PORT))
