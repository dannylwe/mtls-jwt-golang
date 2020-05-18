package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
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
	AccessToken  string
	RefreshToken string
	AccessUUID   string
	RefreshUUID  string
	AtExpires    int64
	RtExpires    int64
}

type AccessDetails struct {
	AccessUUID string
	UserID     uint64
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
	tokens := map[string]string{
		"access_token":  token.AccessToken,
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

// GetTokenFromHeaders gets the jwt token from the Authorization header
func GetTokenFromHeaders(r *http.Request) string {
	bearToken := r.Header.Get("Authorization")
	strArr := strings.Split(bearToken, " ")
	if len(strArr) == 2 {
		return strArr[1]
	}
	return ""
}

// VerifySigningMethod checks whether the signing method of the token is correct. Returns token.
func VerifySigningMethod(r *http.Request) (*jwt.Token, error) {
	tokenString := GetTokenFromHeaders(r)
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing mehtod: %v", token.Header["alg"])
		}
		// fmt.Println(token)
		return []byte(os.Getenv("ACCESS_SECRET")), nil
	})
	if err != nil {
		return nil, err
	}
	// fmt.Println(token)
	return token, nil
}

// ValidateToken checks whether the token is valid
func ValidateToken(r *http.Request) error {
	token, err := VerifySigningMethod(r)
	if err != nil {
		return err
	}
	if _, ok := token.Claims.(jwt.Claims); !ok && !token.Valid {
		return err
	}
	return nil
}

//ExtractTokenMetadata gets the metdata from the token and add it to AccessDetails struct
func ExtractTokenMetadata(r *http.Request) (*AccessDetails, error) {
	token, err := VerifySigningMethod(r)
	if err != nil {
		return nil, err
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if ok && token.Valid {
		accessUUID, ok := claims["access_uuid"].(string)
		if !ok {
			return nil, err
		}
		userID, err := strconv.ParseUint(fmt.Sprintf("%.f", claims["user_id"]), 10, 64)
		if err != nil {
			return nil, err
		}
		return &AccessDetails{
			AccessUUID: accessUUID,
			UserID:     userID,
		}, nil
	}
	return nil, err
}

// FetchAuthFromRedis checks for token in redis. Returns err when token has expired.
func FetchAuthFromRedis(authDetails *AccessDetails) (uint64, error) {
	userid, err := client.Get(authDetails.AccessUUID).Result()
	if err != nil {
		return 0, err
	}
	userID, _ := strconv.ParseUint(userid, 10, 64)
	return userID, nil
}
