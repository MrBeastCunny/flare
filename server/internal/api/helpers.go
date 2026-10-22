package api

import (
	"context"
	"net/http"
	"time"

	"github.com/flare-dns/flare/internal/mail"
)

// Version is set at build time via -ldflags "-X github.com/flare-dns/flare/internal/api.Version=..."
var Version = "dev"

var timeNow = time.Now

// context0 returns a request-derived context that survives client disconnects.
func context0(r *http.Request) context.Context { return context.WithoutCancel(r.Context()) }

func errMailDisabled() error { return mail.ErrNotConfigured }

func mailMessage(to, subject, heading string, body []string, actionText, actionURL string) mail.Message {
	return mail.Message{To: to, Subject: subject, Heading: heading, Body: body, ActionText: actionText, ActionURL: actionURL,
		Footer: "You received this email because of activity on your DNS management account."}
}
