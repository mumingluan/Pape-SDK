package app

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"

	"pape-sdk/internal/config"
	"pape-sdk/internal/store"
)

func TestAddUserReportPersistsCapturedFields(t *testing.T) {
	temp := t.TempDir()
	dataStore, err := store.Open("sqlite://"+filepath.Join(temp, "reports.db"), temp)
	if err != nil {
		t.Fatal(err)
	}
	defer dataStore.Close()
	a := &App{cfg: &config.Config{}, store: dataStore}
	form := url.Values{
		"submitter_role_name": {"举报人"}, "client_ip": {"13"}, "clientid": {"1068"},
		"zoneid": {"1"}, "violation_role_id": {"1009445855"}, "reason_id": {"3"},
		"submitter_role_id": {"1032488907"}, "content": {"test"}, "platform": {"2"},
		"violation_role_name": {"被举报人"}, "timestamp": {"1788534507"}, "source": {"101"}, "region": {"1"},
	}
	request := httptest.NewRequest(http.MethodPost, "https://cspro-api.papegames.com/v1/inform/add", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Host = "cspro-api.papegames.com"
	recorder := httptest.NewRecorder()
	a.publicRouter(true, false).ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var response map[string]any
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil || response["ret"] != float64(0) || response["msg"] != "OK" || response["request_id"] == "" {
		t.Fatalf("response=%#v err=%v", response, err)
	}
	reports, total, err := dataStore.AdminUserReports("1009445855", 20, 0)
	if err != nil || total != 1 || len(reports) != 1 {
		t.Fatalf("reports=%+v total=%d err=%v", reports, total, err)
	}
	report := reports[0]
	if report.Host != "cspro-api.papegames.com" || report.SubmitterRoleName != "举报人" || report.ViolationRoleName != "被举报人" || report.Content != "test" {
		t.Fatalf("report=%+v", report)
	}
}
