package egoutil

import (
	"errors"
	"log"
	"net/http"
)

type ErrorResponse interface {
	Error() string
	Status() int
}

func ErrorResponseStatus(code int) ErrorResponse {
	return errorResponseStatus(code)
}

type errorResponseStatus int

func (s errorResponseStatus) Error() string {
	return http.StatusText(int(s))
}

func (s errorResponseStatus) Status() int {
	return int(s)
}

// HandleError returns true if there was an error and you should stop
func HandleError(w http.ResponseWriter, err error, context ...string) bool {
	if err == nil {
		return false
	}

	log.Println(err)

	var er ErrorResponse
	if errors.As(err, &er) {
		w.WriteHeader(er.Status())
	} else {
		w.WriteHeader(500)
	}

	for _, x := range context {
		w.Write([]byte(x))
		w.Write([]byte{'\n'})
	}
	w.Write([]byte(err.Error()))
	w.Write([]byte{'\n'})

	return true
}
