package middleware

import (
	"a21hc3NpZ25tZW50/model"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt"
)

func Auth() gin.HandlerFunc {
	return gin.HandlerFunc(func(ctx *gin.Context) {
		// Mendapatkan token sesi dari cookie
		tokenString, err := ctx.Cookie("session_token")
		if err != nil {
			// Memeriksa jenis konten yang diterima oleh permintaan
			if ctx.GetHeader("Content-Type") != "application/json" {
				// Mengembalikan respons JSON jika jenis konten tidak valid
				ctx.JSON(http.StatusSeeOther, gin.H{"error": "Invalid content type"})
				ctx.Abort()
				return
			}
			// Mengembalikan respons JSON jika token sesi tidak ditemukan atau tidak valid
			ctx.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
			ctx.Abort()
			return
		}

		// Membuat variabel untuk menyimpan klaim token
		claims := &model.Claims{}

		// Memverifikasi token sesi dengan klaim yang disediakan
		token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
			return []byte(model.JwtKey), nil
		})
		if err != nil {
			// Mengembalikan respons JSON jika token tidak valid
			ctx.JSON(http.StatusBadRequest, gin.H{"error": "Invalid token"})
			ctx.Abort()
			return
		}

		// Memeriksa apakah token sesi valid
		if !token.Valid {
			// Mengembalikan respons JSON jika token sesi tidak valid
			ctx.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
			ctx.Abort()
			return
		}

		// Menetapkan alamat email dari klaim token ke konteks
		ctx.Set("email", claims.Email)

		// Memanggil handler selanjutnya dalam rantai middleware
		ctx.Next()
	})
}
