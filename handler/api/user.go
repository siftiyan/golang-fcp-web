package api

import (
	"a21hc3NpZ25tZW50/model"
	"a21hc3NpZ25tZW50/service"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt"
)

type UserAPI interface {
	Register(c *gin.Context)
	Login(c *gin.Context)
	GetUserTaskCategory(c *gin.Context)
}

type userAPI struct {
	userService service.UserService
}

func NewUserAPI(userService service.UserService) *userAPI {
	return &userAPI{userService}
}

func (u *userAPI) Register(c *gin.Context) {
	var user model.UserRegister

	if err := c.BindJSON(&user); err != nil {
		c.JSON(http.StatusBadRequest, model.NewErrorResponse("invalid decode json"))
		return
	}

	if user.Email == "" || user.Password == "" || user.Fullname == "" {
		c.JSON(http.StatusBadRequest, model.NewErrorResponse("register data is empty"))
		return
	}

	var recordUser = model.User{
		Fullname: user.Fullname,
		Email:    user.Email,
		Password: user.Password,
	}

	recordUser, err := u.userService.Register(&recordUser)
	if err != nil {
		c.JSON(http.StatusInternalServerError, model.NewErrorResponse("error internal server"))
		return
	}

	c.JSON(http.StatusCreated, model.NewSuccessResponse("register success"))
}

func (u *userAPI) Login(c *gin.Context) {
	var user model.UserLogin
	if err := c.BindJSON(&user); err != nil {
		c.JSON(http.StatusBadRequest, model.NewErrorResponse("invalid decode json"))
		return
	}

	if user.Email == "" || user.Password == "" {
		c.JSON(http.StatusBadRequest, model.NewErrorResponse("email or password is empty"))
		return
	}

	var recordUser = model.User{
		Email:    user.Email,
		Password: user.Password,
	}

	// Melakukan login dan menerima token dari service
	tokenStringPtr, err := u.userService.Login(&recordUser)
	if err != nil {
		c.JSON(http.StatusInternalServerError, model.NewErrorResponse("error internal server"))
		return
	}

	// Mengatur waktu kedaluwarsa token (24 jam dari sekarang)
	expirationTime := time.Now().Add(24 * time.Hour)

	// Memeriksa dan menguraikan token string untuk memeriksa validitasnya serta mengekstrak klaim-klaimnya
	token, err := jwt.ParseWithClaims(*tokenStringPtr, &jwt.StandardClaims{}, func(token *jwt.Token) (interface{}, error) {
		return model.JwtKey, nil
	})
	if err != nil {
		c.JSON(http.StatusInternalServerError, model.NewErrorResponse("error internal server"))
		return
	}

	// Memeriksa validitas token dan mengekstrak klaim-klaimnya
	claims, ok := token.Claims.(*jwt.StandardClaims)
	if !ok || !token.Valid {
		c.JSON(http.StatusUnauthorized, model.NewErrorResponse("invalid token"))
		return
	}

	// Memperbarui waktu kedaluwarsa dalam klaim-klaim
	claims.ExpiresAt = expirationTime.Unix()

	// Menyetel token sebagai cookie dalam respons
	http.SetCookie(c.Writer, &http.Cookie{
		Name:    "session_token",
		Value:   *tokenStringPtr,
		Expires: expirationTime,
	})

	// Memberikan respons dengan ID pengguna dan pesan keberhasilan
	c.JSON(http.StatusOK, gin.H{
		"user_id": recordUser.ID,
		"message": "login success",
	})
}

func (u *userAPI) GetUserTaskCategory(c *gin.Context) {
	// Assuming the user's email is retrieved from the authentication token
	email := c.GetString("email")

	if email == "" {
		c.JSON(http.StatusBadRequest, model.NewErrorResponse("email not provided"))
		return
	}

	taskCategories, err := u.userService.GetUserTaskCategory()
	if err != nil {
		c.JSON(http.StatusInternalServerError, model.NewErrorResponse("error getting user task categories"))
		return
	}

	c.JSON(http.StatusOK, taskCategories)
}
