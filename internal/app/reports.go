package app

import (
	"net/http"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"pape-sdk/internal/store"
)

func (a *App) addUserReport(c *gin.Context) {
	requestID := uuid.NewString()
	report := store.UserReport{
		RequestID:         requestID,
		EventTimestamp:    reportFormInt64(c, "timestamp"),
		Host:              clippedReportText(c.Request.Host, 255),
		ObservedIP:        clippedReportText(c.ClientIP(), 64),
		ClientIP:          clippedReportText(c.PostForm("client_ip"), 64),
		ClientID:          reportFormInt64(c, "clientid"),
		ZoneID:            reportFormInt64(c, "zoneid"),
		Region:            reportFormInt64(c, "region"),
		Platform:          reportFormInt64(c, "platform"),
		Source:            reportFormInt64(c, "source"),
		SubmitterRoleID:   reportFormInt64(c, "submitter_role_id"),
		SubmitterRoleName: clippedReportText(c.PostForm("submitter_role_name"), 255),
		ViolationRoleID:   reportFormInt64(c, "violation_role_id"),
		ViolationRoleName: clippedReportText(c.PostForm("violation_role_name"), 255),
		ReasonID:          reportFormInt64(c, "reason_id"),
		Content:           clippedReportText(c.PostForm("content"), 4000),
	}
	if _, err := a.store.CreateUserReport(report); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"ret": 1, "msg": "记录举报失败", "request_id": requestID})
		return
	}
	officialTextJSON(c, gin.H{"ret": 0, "msg": "OK", "data": nil, "request_id": requestID})
}

func reportFormInt64(c *gin.Context, key string) int64 {
	value, _ := strconv.ParseInt(strings.TrimSpace(c.PostForm(key)), 10, 64)
	return value
}

func clippedReportText(value string, maxRunes int) string {
	value = strings.TrimSpace(value)
	if utf8.RuneCountInString(value) <= maxRunes {
		return value
	}
	runes := []rune(value)
	return string(runes[:maxRunes])
}
