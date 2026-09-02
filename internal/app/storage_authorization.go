package app

import (
	"errors"
	"strings"

	"github.com/gin-gonic/gin"

	storageclient "pape-sdk/internal/storage"
)

func (a *App) storageAuthorization(c *gin.Context) {
	form, timestamp, err := a.form(c)
	if err != nil {
		passportError(c, err)
		return
	}
	if a.objectStorage == nil {
		passportError(c, errors.New("对象存储未配置"))
		return
	}
	if _, err := a.userFromFields(form); err != nil {
		passportError(c, err)
		return
	}
	category := strings.TrimSpace(form["category"])
	if category == "" {
		passportError(c, errors.New("缺少对象分类"))
		return
	}
	acquired, err := a.objectStorage.Acquire(c.Request.Context(), storageclient.AcquireRequest{
		ChannelID:        strings.TrimSpace(form["channel_id"]),
		Category:         category,
		OriginalFilename: strings.TrimSpace(form["original_filename"]),
		ObjectName:       strings.TrimSpace(form["file_name"]),
		Extension:        strings.TrimSpace(form["ext"]),
	})
	if err != nil {
		passportError(c, err)
		return
	}
	a.encrypted(c, acquired, timestamp)
}
