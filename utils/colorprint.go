package utils

import (
	"fmt"

	. "github.com/logrusorgru/aurora"
)

func Success(message string) {
	fmt.Println(Cyan("[+]"), message)
}
func SuccessF(message string, args ...interface{}) {
	fmt.Println(Cyan("[+]"), fmt.Sprintf(message, args...))
}

func Failure(message string) {
	fmt.Println(Red("[-]"), message)
}
func FailureF(message string, args ...interface{}) {
	fmt.Println(Red("[-]"), fmt.Sprintf(message, args...))
}

func Exit(message string) {
	fmt.Println(Red("[-]"), message)
}
func ExitF(message string, args ...interface{}) {
	fmt.Println(Red("[-]"), fmt.Sprintf(message, args...))
}
