// package main

// import (
// 	"fmt"
// 	"net/http"

// 	"github.com/gin-gonic/gin"
// 	"golang.org/x/crypto/bcrypt"
// )

// // User represents a user in the system
// type UserPassword struct {
// 	ID       int    `json:"id"`
// 	Username string `json:"username"`
// 	Password string `json:"password"`
// }

// // UpdatePassword updates the password for a user
// func UpdatePassword(c *gin.Context) {
// 	// Get the user ID from the URL parameters
// 	userID := c.Param("id")

// 	// Get the user from the database
// 	var user UserPassword
// 	if err := db.Where("id = ?", userID).First(&user).Error; err != nil {
// 		c.AbortWithStatus(http.StatusNotFound)
// 		return
// 	}

// 	// Bind the new password to a variable
// 	var update struct {
// 		Password string `json:"password"`
// 	}
// 	if err := c.BindJSON(&update); err != nil {
// 		c.AbortWithStatus(http.StatusBadRequest)
// 		return
// 	}

// 	// Hash the new password
// 	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(update.Password), bcrypt.DefaultCost)
// 	if err != nil {
// 		c.AbortWithStatus(http.StatusInternalServerError)
// 		return
// 	}

// 	// Save the new hashed password to the user
// 	user.Password = string(hashedPassword)
// 	if err := db.Save(&user).Error; err != nil {
// 		c.AbortWithStatus(http.StatusInternalServerError)
// 		return
// 	}

// 	c.Status(http.StatusOK)
// }

// func main() {
// 	router := gin.Default()

// 	router.PUT("/users/:id/password", UpdatePassword)

// 	router.Run()
// }
