package middleware

import (
	"a21hc3NpZ25tZW50/model"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt"
)

func Auth() gin.HandlerFunc {
	return gin.HandlerFunc(func(ctx *gin.Context) {
		tokenString, err := ctx.Cookie("session_token")
		if err != nil {
			if ctx.GetHeader("Content-Type") != "application/json" {
				ctx.JSON(http.StatusSeeOther, gin.H{"error": "Invalid content type"})
				ctx.Abort()
				return
			}
			ctx.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
			ctx.Abort()
			return
		}

		claims := &model.Claims{}

		token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
			return []byte(model.JwtKey), nil
		})
		if err != nil {
			ctx.JSON(http.StatusBadRequest, gin.H{"error": "Invalid token"})
			ctx.Abort()
			return
		}

		if !token.Valid {
			ctx.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
			ctx.Abort()
			return
		}

		ctx.Set("email", claims.Email)

		ctx.Next()
	})
}
