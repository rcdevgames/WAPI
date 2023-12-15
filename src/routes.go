package main

import (
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/justinas/alice"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/hlog"
)

type Middleware = alice.Constructor

func (s *server) routes() {

	if *logType == "json" {
		log = zerolog.New(os.Stdout).With().Timestamp().Str("role", filepath.Base(os.Args[0])).Str("host", *address).Logger()
	} else {
		output := zerolog.ConsoleWriter{Out: os.Stdout, TimeFormat: time.RFC3339}
		log = zerolog.New(output).With().Timestamp().Str("role", filepath.Base(os.Args[0])).Str("host", *address).Logger()
	}

	c := alice.New()
	c = c.Append(s.authuser)
	c = c.Append(hlog.NewHandler(log))

	c = c.Append(hlog.AccessHandler(func(r *http.Request, status, size int, duration time.Duration) {
		hlog.FromRequest(r).Info().
			Str("method", r.Method).
			Stringer("url", r.URL).
			Int("status", status).
			Int("size", size).
			Dur("duration", duration).
			Str("userid", r.Context().Value("userinfo").(Values).Get("Id")).
			Msg("Got API Request")
	}))
	c = c.Append(hlog.RemoteAddrHandler("ip"))
	c = c.Append(hlog.UserAgentHandler("user_agent"))
	c = c.Append(hlog.RefererHandler("referer"))
	c = c.Append(hlog.RequestIDHandler("req_id", "Request-Id"))

	m := alice.New()
	m = m.Append(s.authmaster)
	m = m.Append(hlog.NewHandler(log))

	m = m.Append(hlog.AccessHandler(func(r *http.Request, status, size int, duration time.Duration) {
		hlog.FromRequest(r).Info().
			Str("method", r.Method).
			Stringer("url", r.URL).
			Int("status", status).
			Int("size", size).
			Dur("duration", duration).
			Msg("Got API Request")
	}))
	m = m.Append(hlog.RemoteAddrHandler("ip"))
	m = m.Append(hlog.UserAgentHandler("user_agent"))
	m = m.Append(hlog.RefererHandler("referer"))
	m = m.Append(hlog.RequestIDHandler("req_id", "Request-Id"))

	s.router.Handle("/puteri/register", m.Then(s.PuteriRegister())).Methods("POST")
	s.router.Handle("/puteri/auth", c.Then(s.PuteriAuth())).Methods("GET")
	s.router.Handle("/puteri/logout", c.Then(s.PuteriLogout())).Methods("GET")
	s.router.Handle("/puteri/send", c.Then(s.PuteriSend())).Methods("POST")
	s.router.Handle("/puteri/send-msg", c.Then(s.PuteriSendMsg())).Methods("POST")
}
