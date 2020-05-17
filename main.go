package main

import (
	"log"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	"github.com/go-redis/redis/v7"
	"github.com/twinj/uuid"
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

type TokenDetails struct {
	AccessToken string
	RefreshToken string
	AccessUUID string
	RefreshUUID string
	AtExpires int64
	RtExpires int64
}

var client *redis.Client

func init() {
	dsn := os.Getenv("REDIS_DSN")
	if len(dsn) == 0 {
		dsn = "localhost:6379"
	}

	client = redis.NewClient(&redis.Options{
		Addr: dsn,
	})

	_, err := client.Ping().Result()
	if err != nil {
		panic(err)
	}
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
	
	redisErr := CreateAuth(user.ID, token)
	if redisErr != nil {
		c.JSON(http.StatusUnprocessableEntity, redisErr.Error())
	}
	tokens := map[string]string {
		"access_token": token.AccessToken,
		"refresh_token": token.RefreshToken,
	}
	c.JSON(http.StatusOK, tokens)
}

// CreateToken function generates and returns a jwt token
func CreateToken(userid uint64) (*TokenDetails, error) {
	var err error
	os.Setenv("ACCESS_SECRET", "fwihbfikwfbhi") // TODO: should be set in .env

	td := &TokenDetails{}
	td.AtExpires = time.Now().Add(time.Minute * 15).Unix()
	td.RtExpires = time.Now().Add(time.Hour * 24).Unix()
	td.AccessUUID = uuid.NewV4().String()
	td.RefreshUUID = uuid.NewV4().String()

	claims := jwt.MapClaims{}
	claims["authorized"] = true
	claims["access_uuid"] = td.AccessUUID
	claims["user_id"] = userid
	claims["exp"] = td.AtExpires 

	sign := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	td.AccessToken, err = sign.SignedString([]byte(os.Getenv("ACCESS_SECRET")))

	if err != nil {
		return nil, err
	}

	// create refresh token
	os.Setenv("REFRESH_SECRET", "nfowuhfnowjfnoweifn")
	rtClaims := jwt.MapClaims{}
	rtClaims["refresh_uuid"] = td.RefreshUUID
	rtClaims["user_id"] = userid
	rtClaims["exp"] = td.RtExpires

	refresh := jwt.NewWithClaims(jwt.SigningMethodHS256, rtClaims)
	td.RefreshToken, err = refresh.SignedString([]byte(os.Getenv("REFRESH_SECRET")))

	if err != nil {
		return nil, err
	}
	return td, nil
}

// CreateAuth saves JWT metadata in redis
func CreateAuth(userid uint64, td *TokenDetails) error {
	// converting to unix UTC
	at := time.Unix(td.AtExpires, 0)
	rt := time.Unix(td.RtExpires, 0)
	now := time.Now()

	errAccess := client.Set(td.AccessUUID, strconv.Itoa(int(userid)), at.Sub(now)).Err()
	if errAccess != nil {
		return errAccess
	}

	errRefresh := client.Set(td.RefreshUUID, strconv.Itoa(int(userid)), rt.Sub(now)).Err()
    if errRefresh != nil {
        return errRefresh
    }
    return nil
}
