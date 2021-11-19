package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"net/http"

	"github.com/gin-gonic/gin"
)

type SaveRequestBody struct {
	UserName         string `json:"user_name"`
	EncodedSignature string `json:"signature"`
}

var encodedPublicKey = "nVk2y5okFLAlxY0FQrn+Ao7cALgFLTiAqUHOlXZR4JU="

// var encodedPrivateKey = "ltVQ/Rx52hgQ9vDh8ZCiqFV+x6IZGviuAZivo+Ads7KdWTbLmiQUsCXFjQVCuf4CjtwAuAUtOICpQc6VdlHglQ=="

func getPublicKey() (ed25519.PublicKey, error) {
	decoded, err := base64.StdEncoding.DecodeString(encodedPublicKey)

	if err != nil {
		return nil, err
	}

	return ed25519.PublicKey(decoded), nil
}

func decodeSignature(signature string) ([]byte, error) {
	decoded, err := base64.StdEncoding.DecodeString(signature)

	if err != nil {
		return nil, err
	}

	return decoded, nil
}

func main() {
	router := gin.Default()

	router.POST("/save", save)

	router.Run()
}

func save(context *gin.Context) {
	publicKey, err := getPublicKey()

	if err != nil {
		context.JSON(http.StatusInternalServerError, gin.H{"error": "Internal Server Error"})
		return
	}

	var requestBody SaveRequestBody
	context.BindJSON(&requestBody)

	decodedSignature, err := decodeSignature(requestBody.EncodedSignature)

	if err != nil {
		context.JSON(http.StatusBadRequest, gin.H{"error": "Invalid signature"})
		return
	}

	validSignature := ed25519.Verify(publicKey, []byte(requestBody.UserName), decodedSignature)

	if validSignature {
		context.JSON(http.StatusOK, gin.H{"message": "Name updated successfully"})
	} else {
		context.JSON(http.StatusBadRequest, gin.H{"message": "Invalid signature"})
	}
}
