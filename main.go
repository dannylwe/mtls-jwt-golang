package main

import (
	"log"
	"net/http"
	"os"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
)

type User struct {
	ID       uint64 `json:"id"`
	Username string `json:username`
	Password string `json:password`
}

var user = User{
	ID:       1,
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

// Login authenticates a user a returns a JWT token
func Login(c *gin.Context) {
	var userLogin User
	if err := c.ShouldBindJSON(&userLogin); err != nil {
		c.JSON(http.StatusUnprocessableEntity, "Invalid Json provided")
		return
	}

	if userLogin.Username != user.Username || userLogin.Password != user.Username {
		c.JSON(http.StatusUnauthorized, "Please provide valid login credentials")
		return
	}

	token, err := CreateToken(user.ID)
	if err != nil {
		c.JSON(http.StatusUnprocessableEntity, err.Error())
		return
	}
	c.JSON(http.StatusOK, token)
}

// CreateToken function generates and returns a jwt token
func CreateToken(userid uint64) (string, error) {
	var err error
	os.Setenv("ACCESS_SECRET", "fwihbfikwfbhi") // TODO: should be set in .env

	claims := jwt.MapClaims{}
	claims["authorized"] = true
	claims["user_id"] = userid
	claims["exp"] = time.Now().Add(time.Minute * 15).Unix()

	sign := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	token, err := sign.SignedString([]byte(os.Getenv("ACCESS_SECRET")))

	if err != nil {
		return "", err
	}
	return token, nil
}
