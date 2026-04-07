package handler

import (
	"context"
	"encoding/json"
	"log"

	auditdomain "idp-server/internal/domain/audit"
	sessiondomain "idp-server/internal/domain/session"
	userdomain "idp-server/internal/domain/user"
	httpmiddleware "idp-server/internal/interfaces/http/middleware"
	"idp-server/internal/ports/repository"

	"github.com/gin-gonic/gin"
)

type adminAuditContext struct {
	User      *userdomain.Model
	Session   *sessiondomain.Model
	IPAddress string
	UserAgent string
}

func currentAdminAuditContext(c *gin.Context) *adminAuditContext {
	if c == nil {
		return nil
	}
	user := httpmiddleware.CurrentAdminUser(c)
	if user == nil {
		return nil
	}
	return &adminAuditContext{
		User:      user,
		Session:   httpmiddleware.CurrentAdminSession(c),
		IPAddress: c.ClientIP(),
		UserAgent: c.Request.UserAgent(),
	}
}

func recordAdminAuditEvent(ctx context.Context, repo repository.AuditEventRepository, actor *adminAuditContext, eventType, subject string, metadata map[string]any) {
	if repo == nil || actor == nil || actor.User == nil {
		return
	}

	metadataJSON := ""
	if len(metadata) > 0 {
		data, err := json.Marshal(metadata)
		if err != nil {
			log.Printf("audit_event marshal failed event_type=%s actor_user_id=%d err=%v", eventType, actor.User.ID, err)
		} else {
			metadataJSON = string(data)
		}
	}

	model := &auditdomain.Model{
		EventType:    eventType,
		UserID:       ptrInt64(actor.User.ID),
		Subject:      subject,
		IPAddress:    actor.IPAddress,
		UserAgent:    actor.UserAgent,
		MetadataJSON: metadataJSON,
	}
	if actor.Session != nil && actor.Session.ID > 0 {
		model.SessionID = ptrInt64(actor.Session.ID)
	}
	if err := repo.Create(ctx, model); err != nil {
		log.Printf("audit_event create failed event_type=%s actor_user_id=%d subject=%s err=%v", eventType, actor.User.ID, subject, err)
	}
}

func ptrInt64(value int64) *int64 {
	return &value
}
