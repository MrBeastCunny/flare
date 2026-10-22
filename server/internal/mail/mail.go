// Package mail sends transactional email over SMTP.
package mail

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"html/template"
	"mime/quotedprintable"
	"net"
	"net/smtp"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	Host         string
	Port         int
	Username     string
	Password     string
	From         string
	TLS          string // starttls | tls | none
	InstanceName string
}

func (c Config) Enabled() bool { return c.Host != "" && c.From != "" }

type Mailer struct {
	config func(ctx context.Context) (Config, error)
}

func New(cfg func(ctx context.Context) (Config, error)) *Mailer { return &Mailer{config: cfg} }

var ErrNotConfigured = errors.New("email delivery is not configured")

func (m *Mailer) Enabled(ctx context.Context) bool {
	c, err := m.config(ctx)
	return err == nil && c.Enabled()
}

// Message is a simple transactional email with a single call to action.
type Message struct {
	To         string
	Subject    string
	Heading    string
	Body       []string
	ActionText string
	ActionURL  string
	Footer     string
}

var htmlTpl = template.Must(template.New("mail").Parse(`<!doctype html>
<html><body style="margin:0;padding:24px;background:#f7f7f7;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Helvetica,Arial,sans-serif;color:#1a1a1a">
<table role="presentation" width="100%" cellspacing="0" cellpadding="0"><tr><td align="center">
<table role="presentation" width="560" cellspacing="0" cellpadding="0" style="background:#ffffff;border:1px solid #e5e5e5;border-radius:8px">
<tr><td style="padding:24px 32px;border-bottom:1px solid #eeeeee;font-weight:600;font-size:16px;color:#b0102f">{{.Instance}}</td></tr>
<tr><td style="padding:32px">
<h1 style="margin:0 0 16px;font-size:20px;font-weight:600">{{.Heading}}</h1>
{{range .Body}}<p style="margin:0 0 12px;font-size:14px;line-height:1.5">{{.}}</p>{{end}}
{{if .ActionURL}}<p style="margin:24px 0"><a href="{{.ActionURL}}" style="display:inline-block;background:#c8102e;color:#ffffff;text-decoration:none;padding:10px 18px;border-radius:6px;font-size:14px;font-weight:500">{{.ActionText}}</a></p>
<p style="margin:0;font-size:12px;color:#666666;word-break:break-all">Or paste this link into your browser: {{.ActionURL}}</p>{{end}}
</td></tr>
{{if .Footer}}<tr><td style="padding:16px 32px;border-top:1px solid #eeeeee;font-size:12px;color:#777777">{{.Footer}}</td></tr>{{end}}
</table></td></tr></table></body></html>`))

func (m *Mailer) Send(ctx context.Context, msg Message) error {
	cfg, err := m.config(ctx)
	if err != nil {
		return err
	}
	if !cfg.Enabled() {
		return ErrNotConfigured
	}
	var html bytes.Buffer
	if err := htmlTpl.Execute(&html, map[string]any{
		"Instance": cfg.InstanceName, "Heading": msg.Heading, "Body": msg.Body,
		"ActionText": msg.ActionText, "ActionURL": msg.ActionURL, "Footer": msg.Footer,
	}); err != nil {
		return err
	}
	text := msg.Heading + "\n\n" + strings.Join(msg.Body, "\n\n")
	if msg.ActionURL != "" {
		text += "\n\n" + msg.ActionText + ": " + msg.ActionURL
	}
	if msg.Footer != "" {
		text += "\n\n--\n" + msg.Footer
	}

	boundary := fmt.Sprintf("flare-%d", time.Now().UnixNano())
	var buf bytes.Buffer
	fmt.Fprintf(&buf, "From: %s\r\nTo: %s\r\nSubject: %s\r\nDate: %s\r\nMIME-Version: 1.0\r\n",
		cfg.From, msg.To, msg.Subject, time.Now().Format(time.RFC1123Z))
	fmt.Fprintf(&buf, "Content-Type: multipart/alternative; boundary=%q\r\n\r\n", boundary)
	for _, part := range []struct{ ct, body string }{{"text/plain", text}, {"text/html", html.String()}} {
		fmt.Fprintf(&buf, "--%s\r\nContent-Type: %s; charset=utf-8\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\n", boundary, part.ct)
		qp := quotedprintable.NewWriter(&buf)
		_, _ = qp.Write([]byte(part.body))
		_ = qp.Close()
		buf.WriteString("\r\n")
	}
	fmt.Fprintf(&buf, "--%s--\r\n", boundary)
	return deliver(ctx, cfg, msg.To, buf.Bytes())
}

func deliver(ctx context.Context, cfg Config, to string, body []byte) error {
	addr := net.JoinHostPort(cfg.Host, strconv.Itoa(cfg.Port))
	d := net.Dialer{Timeout: 15 * time.Second}
	var conn net.Conn
	var err error
	tlsCfg := &tls.Config{ServerName: cfg.Host, MinVersion: tls.VersionTLS12}
	if cfg.TLS == "tls" {
		conn, err = tls.DialWithDialer(&d, "tcp", addr, tlsCfg)
	} else {
		conn, err = d.DialContext(ctx, "tcp", addr)
	}
	if err != nil {
		return fmt.Errorf("smtp dial: %w", err)
	}
	_ = conn.SetDeadline(time.Now().Add(60 * time.Second))
	c, err := smtp.NewClient(conn, cfg.Host)
	if err != nil {
		return fmt.Errorf("smtp: %w", err)
	}
	defer c.Close()
	if cfg.TLS == "starttls" {
		if err := c.StartTLS(tlsCfg); err != nil {
			return fmt.Errorf("smtp starttls: %w", err)
		}
	}
	if cfg.Username != "" {
		if err := c.Auth(smtp.PlainAuth("", cfg.Username, cfg.Password, cfg.Host)); err != nil {
			return fmt.Errorf("smtp auth: %w", err)
		}
	}
	from := cfg.From
	if i := strings.LastIndex(from, "<"); i >= 0 {
		from = strings.TrimSuffix(from[i+1:], ">")
	}
	if err := c.Mail(from); err != nil {
		return err
	}
	if err := c.Rcpt(to); err != nil {
		return err
	}
	w, err := c.Data()
	if err != nil {
		return err
	}
	if _, err := w.Write(body); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	return c.Quit()
}
