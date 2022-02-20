package structs

import "net/http"

type RequestCache struct {
	Request       *http.Request
	ProtoRequest  *Request
	ProtoResponse *Response
}
