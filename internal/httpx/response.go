package httpx

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

func WithGenerated(m map[string]any, includeMsg bool) map[string]any {
	out := make(map[string]any, len(m)+4)
	for k, v := range m {
		if k == "ret" || k == "time" || k == "msg" || k == "request_id" {
			continue
		}
		out[k] = v
	}
	out["ret"] = 0
	out["time"] = time.Now().Unix()
	if includeMsg {
		out["request_id"] = uuid.NewString()
		out["msg"] = "OK"
	}
	return out
}

func Envelope(data any) gin.H {
	out := gin.H{"code": 0, "info": "OK", "request_id": uuid.NewString()}
	if data != nil {
		out["data"] = data
	}
	return out
}

func ErrorEnvelope(code int, info string) gin.H {
	return gin.H{"code": code, "info": info, "request_id": uuid.NewString()}
}

func JSON(c *gin.Context, payload any) {
	c.JSON(http.StatusOK, payload)
}
