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

func Message(message string) {
	fmt.Println(Gray(8, "[#]"), message)
}
func MessageF(message string, args ...interface{}) {
	fmt.Println(Gray(8, "[#]"), fmt.Sprintf(message, args...))
}

func Question(message string) {
	fmt.Print(Yellow("[?]"), message)
}
func QuestionF(message string, args ...interface{}) {
	fmt.Print(Yellow("[?]"), fmt.Sprintf(message, args...))
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
