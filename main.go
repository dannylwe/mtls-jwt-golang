package main

import (
	"log"
	"net/http"

	"github.com/gin-gonic/gin"
)

type User struct {
	ID uint64 `json:"id"`
	Username string `json:username`
	Password string `json:password`
}

var user = User {
	ID: 1,
	Username: "admin",
	Password: "admin",
}

func main() {
	router := gin.Default()
	router.GET("/ping", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"message": "pong",
		})
	})

	router.POST("/login", Login)
	// runs on 0.0.0.0:8080 for windows
	log.Fatal(router.Run(":8080"))
}

func Login(c *gin.Context){
	var userLogin User
	if err := c.ShouldBindJSON(&userLogin); err != nil {
		c.JSON(http.StatusUnprocessableEntity, "Invalid Json provided")
		return
	}

	if userLogin.Username != user.Username || userLogin.Password != user.Username {
		c.JSON(http.StatusUnauthorized, "Please provide valid login credentials")
		return
	}
}
