package utils

import (
	"fmt"

	"github.com/gookit/color"
)

func Success(message string) {
	color.Println("<cyan>[+]</> " + message)
}
func SuccessF(message string, args ...interface{}) {
	color.Println("<cyan>[+]</> " + fmt.Sprintf(message, args...))
}

func Failure(message string) {
	color.Println("<red>[-]</> " + message)
}
func FailureF(message string, args ...interface{}) {
	color.Println("<red>[-]</> " + fmt.Sprintf(message, args...))
}
