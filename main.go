package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"net/http"

	"github.com/gin-gonic/gin"
)

type SaveRequestBody struct {
	UserName   string `json:"user_name"`
	MessageMAC string `json:"messageMAC"`
}

const invalidMACMessage string = "Invalid MAC Provided"

func main() {
	router := gin.Default()

	router.POST("/save", save)

	router.Run()
}

func save(context *gin.Context) {
	signing_key := "arpit"

	var requestBody SaveRequestBody
	context.BindJSON(&requestBody)

	messageMAC, err := base64.StdEncoding.DecodeString(requestBody.MessageMAC)

	if err != nil {
		context.JSON(http.StatusBadRequest, gin.H{"error": invalidMACMessage})
		return
	}

	if ValidMAC(requestBody.UserName, messageMAC, signing_key) {
		context.JSON(http.StatusOK, gin.H{"message": "Name updated succesfully"})
	} else {
		context.JSON(http.StatusBadRequest, gin.H{"error": invalidMACMessage})
	}
}

func ValidMAC(message string, messageMAC []byte, key string) bool {
	mac := hmac.New(sha256.New, []byte(key))
	mac.Write([]byte(message))
	expectedMAC := mac.Sum(nil)
	return hmac.Equal(messageMAC, expectedMAC)
}
