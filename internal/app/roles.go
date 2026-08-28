package app

import (
	"strconv"
	"time"

	"github.com/gin-gonic/gin"

	"pape-sdk/internal/httpx"
	"pape-sdk/internal/store"
)

func (a *App) roleList(c *gin.Context) {
	user, err := a.roleUser(c)
	if err != nil {
		c.JSON(200, httpx.Envelope(gin.H{"roles": []any{}, "rolelist": []any{}}))
		return
	}
	profiles, err := a.booi.Roles(c.Request.Context(), user.OpenID)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	roles := make([]gin.H, 0, len(profiles))
	for _, profile := range profiles {
		roles = append(roles, gin.H{
			"ServerID": profile.ServerID, "server_id": profile.ServerID,
			"Uid": profile.AccountID, "uid": profile.AccountID,
			"ZoneID": profile.ZoneID, "zone_id": profile.ZoneID,
			"Name": profile.Name, "name": profile.Name,
			"FamilyName": profile.FamilyName, "family_name": profile.FamilyName,
			"Level": profile.Level, "level": profile.Level,
			"CTime": profile.CreatedAt, "LastRefreshTime": profile.LastLoginAt,
		})
	}
	c.JSON(200, httpx.Envelope(gin.H{"roles": roles, "rolelist": roles}))
}

func (a *App) roleUser(c *gin.Context) (store.User, error) {
	form, _, err := a.form(c)
	if err != nil {
		return store.User{}, err
	}
	return a.userFromFields(form)
}

func (a *App) roleInfo(c *gin.Context) {
	form, _, err := a.form(c)
	if err != nil {
		passportError(c, err)
		return
	}
	user, err := a.userFromFields(form)
	if err != nil {
		passportError(c, err)
		return
	}
	profiles, err := a.booi.Roles(c.Request.Context(), user.OpenID)
	if err != nil {
		passportError(c, err)
		return
	}
	roleInfo := gin.H{}
	for _, profile := range profiles {
		roleInfo[strconv.FormatUint(uint64(profile.ZoneID), 10)] = gin.H{
			"ServerID":   profile.ServerID,
			"Uid":        profile.AccountID,
			"ZoneID":     profile.ZoneID,
			"Name":       profile.Name,
			"FamilyName": profile.FamilyName,
			"Level":      profile.Level, "LastRefreshTime": profile.LastLoginAt, "CTime": profile.CreatedAt,
		}
	}
	officialTextJSON(c, gin.H{"ret": 0, "roleinfo": roleInfo, "time": time.Now().Unix()})
}
