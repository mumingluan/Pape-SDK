package store

import (
	"strings"
	"time"
)

type UserReport struct {
	ID                int64  `json:"id"`
	RequestID         string `json:"request_id"`
	CreatedAt         int64  `json:"created_at"`
	EventTimestamp    int64  `json:"event_timestamp"`
	Host              string `json:"host"`
	ObservedIP        string `json:"observed_ip"`
	ClientIP          string `json:"client_ip"`
	ClientID          int64  `json:"client_id"`
	ZoneID            int64  `json:"zone_id"`
	Region            int64  `json:"region"`
	Platform          int64  `json:"platform"`
	Source            int64  `json:"source"`
	SubmitterRoleID   int64  `json:"submitter_role_id"`
	SubmitterRoleName string `json:"submitter_role_name"`
	ViolationRoleID   int64  `json:"violation_role_id"`
	ViolationRoleName string `json:"violation_role_name"`
	ReasonID          int64  `json:"reason_id"`
	Content           string `json:"content"`
}

func (s *Store) CreateUserReport(report UserReport) (UserReport, error) {
	if report.CreatedAt == 0 {
		report.CreatedAt = time.Now().Unix()
	}
	result, err := s.db.Exec(`insert into user_reports(
		request_id, created_at, event_timestamp, host, observed_ip, client_ip,
		client_id, zone_id, region, platform, source,
		submitter_role_id, submitter_role_name, violation_role_id, violation_role_name,
		reason_id, content
	) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		report.RequestID, report.CreatedAt, report.EventTimestamp, report.Host, report.ObservedIP, report.ClientIP,
		report.ClientID, report.ZoneID, report.Region, report.Platform, report.Source,
		report.SubmitterRoleID, report.SubmitterRoleName, report.ViolationRoleID, report.ViolationRoleName,
		report.ReasonID, report.Content,
	)
	if err != nil {
		return UserReport{}, err
	}
	report.ID, err = result.LastInsertId()
	return report, err
}

func (s *Store) AdminUserReports(query string, limit, offset int) ([]UserReport, int64, error) {
	if limit <= 0 || limit > 200 {
		limit = 100
	}
	if offset < 0 {
		offset = 0
	}
	query = strings.TrimSpace(query)
	pattern := "%" + query + "%"
	filter := `(? = '' or submitter_role_name like ? or violation_role_name like ? or content like ?
		or cast(submitter_role_id as char) like ? or cast(violation_role_id as char) like ?
		or cast(reason_id as char) like ? or request_id like ?)`
	args := []any{query, pattern, pattern, pattern, pattern, pattern, pattern, pattern}
	var total int64
	if err := s.db.QueryRow("select count(*) from user_reports where "+filter, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	rows, err := s.db.Query(`select id, request_id, created_at, event_timestamp, host, observed_ip, client_ip,
		client_id, zone_id, region, platform, source,
		submitter_role_id, submitter_role_name, violation_role_id, violation_role_name, reason_id, content
		from user_reports where `+filter+` order by created_at desc, id desc limit ? offset ?`, append(args, limit, offset)...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	reports := []UserReport{}
	for rows.Next() {
		var report UserReport
		if err := rows.Scan(
			&report.ID, &report.RequestID, &report.CreatedAt, &report.EventTimestamp, &report.Host, &report.ObservedIP, &report.ClientIP,
			&report.ClientID, &report.ZoneID, &report.Region, &report.Platform, &report.Source,
			&report.SubmitterRoleID, &report.SubmitterRoleName, &report.ViolationRoleID, &report.ViolationRoleName,
			&report.ReasonID, &report.Content,
		); err != nil {
			return nil, 0, err
		}
		reports = append(reports, report)
	}
	return reports, total, rows.Err()
}
