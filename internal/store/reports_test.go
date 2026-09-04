package store

import (
	"path/filepath"
	"testing"
)

func TestUserReportHistory(t *testing.T) {
	temp := t.TempDir()
	s, err := Open("sqlite://"+filepath.Join(temp, "reports.db"), temp)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	report, err := s.CreateUserReport(UserReport{
		RequestID: "report-1", EventTimestamp: 1788534507, Host: "cspro-api.papegames.com",
		ObservedIP: "127.0.0.1", ClientIP: "13", ClientID: 1068, ZoneID: 1, Region: 1,
		Platform: 2, Source: 101, SubmitterRoleID: 1032488907, SubmitterRoleName: "举报人",
		ViolationRoleID: 1009445855, ViolationRoleName: "被举报人", ReasonID: 3, Content: "test",
	})
	if err != nil || report.ID == 0 || report.CreatedAt == 0 {
		t.Fatalf("created report=%+v err=%v", report, err)
	}
	reports, total, err := s.AdminUserReports("被举报人", 20, 0)
	if err != nil || total != 1 || len(reports) != 1 {
		t.Fatalf("reports=%+v total=%d err=%v", reports, total, err)
	}
	if reports[0].RequestID != "report-1" || reports[0].ReasonID != 3 || reports[0].Content != "test" {
		t.Fatalf("stored report=%+v", reports[0])
	}
}
