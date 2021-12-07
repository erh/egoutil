package egoutil

import (
	"context"
	"crypto/rand"
	"embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io/fs"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Masterminds/sprig"
	"go.uber.org/multierr"

	"golang.org/x/oauth2"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.mongodb.org/mongo-driver/mongo/readpref"

	"github.com/coreos/go-oidc/v3/oidc"

	"go.opencensus.io/trace"
	"goji.io"
	"goji.io/pat"
)

type UserInfo struct {
	LoggedIn   bool
	Properties map[string]interface{}
}

func (u *UserInfo) GetEmail() string {
	if u.Properties == nil {
		return ""
	}
	s, ok := u.Properties["email"].(string)
	if !ok {
		return ""
	}
	return s
}

func (u *UserInfo) GetEmailVerified() bool {
	if u.Properties == nil {
		return false
	}
	b, ok := u.Properties["email_verified"].(bool)
	if !ok {
		return false
	}
	return b
}

func (u *UserInfo) GetBool(name string) bool {
	if u.Properties == nil {
		return false
	}

	v, found := u.Properties[name]
	if !found {
		return false
	}

	b, good := v.(bool)
	if !good {
		return false
	}

	return b
}

// ----

type SimpleWebAppConfig struct {
	templateSrcDir string
	templateEmebd  *embed.FS

	mongoURL string

	auth0Domain   string
	auth0ClientId string
	auth0Secret   string

	webRoot string
}

func NewSimpleWebAppConfig(templateDir string) *SimpleWebAppConfig {
	return &SimpleWebAppConfig{
		templateSrcDir: templateDir,
	}
}

func (c *SimpleWebAppConfig) SetTemplateEmbed(embeddedTemplate *embed.FS) *SimpleWebAppConfig {
	c.templateEmebd = embeddedTemplate
	return c
}

func (c *SimpleWebAppConfig) SetMongoURL(url string) *SimpleWebAppConfig {
	c.mongoURL = url
	return c
}

func (c *SimpleWebAppConfig) SetAuth0Domain(s string) *SimpleWebAppConfig {
	c.auth0Domain = s
	return c
}

func (c *SimpleWebAppConfig) SetAuth0ClientId(s string) *SimpleWebAppConfig {
	c.auth0ClientId = s
	return c
}

func (c *SimpleWebAppConfig) SetAuth0Secret(s string) *SimpleWebAppConfig {
	c.auth0Secret = s
	return c
}

func (c *SimpleWebAppConfig) SetWebRoot(s string) *SimpleWebAppConfig {
	c.webRoot = s
	return c
}

// -----

type SimpleWebApp struct {
	config     *SimpleWebAppConfig
	webRootURL *url.URL

	cachedTemplates *template.Template

	MongoClient *mongo.Client

	Mux *goji.Mux

	sessions *SessionManager

	authOIConfig       *oidc.Config
	authConfig         oauth2.Config
	auth0HTTPTransport *http.Transport
}

func NewSimpleWebApp(ctx context.Context, cfg *SimpleWebAppConfig) (*SimpleWebApp, error) {
	var err error

	a := &SimpleWebApp{}
	a.config = cfg
	a.webRootURL, err = url.Parse(a.config.webRoot)
	if err != nil {
		return nil, err
	}

	// templates
	err = a.initTemplates()
	if err != nil {
		return nil, err
	}

	// mongo
	if len(cfg.mongoURL) > 0 {
		a.MongoClient, err = mongo.Connect(ctx, options.Client().ApplyURI(cfg.mongoURL))
		if err != nil {
			return nil, err
		}
		if err := a.MongoClient.Ping(ctx, readpref.Primary()); err != nil {
			return nil, multierr.Combine(err, a.MongoClient.Disconnect(context.Background()))
		}

		// init session store
		a.sessions = NewSessionManager(&MongoDBSessionStore{a.MongoClient.Database("web").Collection("sessions"), nil})
	}

	// muxer
	a.Mux = goji.NewMux()

	// auth0
	err = a.initAuth0(ctx)
	if err != nil {
		return nil, err
	}

	return a, nil
}

func (app *SimpleWebApp) Close() error {
	var err error
	if app.MongoClient != nil {
		err = multierr.Combine(err, app.MongoClient.Disconnect(context.Background()))
	}
	if app.auth0HTTPTransport != nil {
		app.auth0HTTPTransport.CloseIdleConnections()
	}
	// mongo driver uses http.DefaultClient with no way to supply our own (like auth0 does).
	http.DefaultClient.CloseIdleConnections()
	return err
}

func (app *SimpleWebApp) initAuth0(ctx context.Context) error {
	if len(app.config.auth0Domain) == 0 {
		return nil
	}

	if app.config.webRoot == "" {
		return fmt.Errorf("need a webRoot in orde to use auth0")
	}

	// init auth
	app.authOIConfig = &oidc.Config{
		ClientID: app.config.auth0ClientId,
	}

	var httpTransport http.Transport
	ctx = oidc.ClientContext(ctx, &http.Client{Transport: &httpTransport})

	p, err := app.NewAuthProvder(ctx)
	if err != nil {
		httpTransport.CloseIdleConnections()
		return err
	}
	app.auth0HTTPTransport = &httpTransport

	app.authConfig = oauth2.Config{
		ClientID:     app.config.auth0ClientId,
		ClientSecret: app.config.auth0Secret,
		RedirectURL:  app.config.webRoot + "/callback",
		Endpoint:     p.Endpoint(),
		Scopes:       []string{oidc.ScopeOpenID, "profile", "email"},
	}

	app.Mux.Handle(pat.New("/callback"), &CallbackHandler{app})
	app.Mux.Handle(pat.New("/login"), &LoginHandler{app})
	app.Mux.Handle(pat.New("/logout"), &LogoutHandler{app})

	return nil
}

func (app *SimpleWebApp) GetLoggedInUserInfo(r *http.Request) (UserInfo, error) {
	ui := UserInfo{LoggedIn: false, Properties: map[string]interface{}{"email": ""}}
	if app.sessions == nil {
		return ui, nil
	}

	session, err := app.sessions.Get(r, false)
	if err != nil {
		return ui, err
	}

	if session == nil {
		return ui, nil
	}

	v := session.Data["profile"]
	if v == nil {
		return ui, err
	}

	ui.LoggedIn = true
	ui.Properties = v.(bson.M)

	if ui.Properties == nil {
		log.Printf("how is properties nil for %v", r)
	}

	return ui, nil
}

func (app *SimpleWebApp) NewAuthProvder(ctx context.Context) (*oidc.Provider, error) {
	p, err := oidc.NewProvider(ctx, app.config.auth0Domain)
	if err != nil {
		return nil, fmt.Errorf("failed to get provider: %v", err)
	}
	return p, nil
}

func baseTemplate() *template.Template {
	return template.New("app").Funcs(sprig.FuncMap())
}

func fixFiles(files []fs.DirEntry, root string) []string {
	newFiles := []string{}
	for _, e := range files {
		x := e.Name()
		if strings.ContainsAny(x, "#~") {
			continue
		}

		newFiles = append(newFiles, filepath.Join(root, x))
	}
	return newFiles
}

func (app *SimpleWebApp) initTemplates() error {
	if app.config.templateEmebd == nil {
		return nil
	}

	files, err := app.config.templateEmebd.ReadDir(app.config.templateSrcDir)
	if err != nil {
		return err
	}

	newFiles := fixFiles(files, app.config.templateSrcDir)

	app.cachedTemplates, err = baseTemplate().ParseFS(app.config.templateEmebd, newFiles...)
	if err != nil {
		return fmt.Errorf("error initializing templates from embedded filesystem: %w", err)
	}

	return nil
}

func (app *SimpleWebApp) getMainTemplate() (*template.Template, error) {
	if app.cachedTemplates != nil {
		return app.cachedTemplates, nil
	}

	files, err := os.ReadDir(app.config.templateSrcDir)
	if err != nil {
		return nil, err
	}

	newFiles := fixFiles(files, app.config.templateSrcDir)

	return baseTemplate().ParseFiles(newFiles...)
}

func (app *SimpleWebApp) LookupTemplate(name string) (*template.Template, error) {
	t, err := app.getMainTemplate()
	if err != nil {
		return nil, err
	}
	t = t.Lookup(name)
	if t == nil {
		return nil, fmt.Errorf("cannot find template %s", name)
	}
	return t, nil
}

type ErrorResponse interface {
	Error() string
	Status() int
}

func ErrorResponseStatus(code int) ErrorResponse {
	return errorResponseStatus(code)
}

type errorResponseStatus int

func (s errorResponseStatus) Error() string {
	return http.StatusText(int(s))
}

func (s errorResponseStatus) Status() int {
	return int(s)
}

func (app *SimpleWebApp) HandleError(w http.ResponseWriter, err error, context ...string) bool {
	if err == nil {
		return false
	}

	log.Println(err)

	var er ErrorResponse
	if errors.As(err, &er) {
		w.WriteHeader(er.Status())
	} else {
		w.WriteHeader(500)
	}

	for _, x := range context {
		w.Write([]byte(x))
		w.Write([]byte{'\n'})
	}
	w.Write([]byte(err.Error()))
	w.Write([]byte{'\n'})

	return true
}

func (app *SimpleWebApp) HandleAPIError(w http.ResponseWriter, err error, extra interface{}) bool {
	if err == nil {
		return false
	}

	log.Printf("api error: %s %s\n", err, extra)

	data := map[string]interface{}{"err": err.Error()}
	if extra != nil {
		data["extra"] = extra
	}

	js, err := json.Marshal(data)
	if err != nil {
		temp := fmt.Sprintf("err not able to be converted to json (%s) (%s)", data, err)
		w.WriteHeader(500)
		w.Write([]byte(temp))

	} else {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(500)
		w.Write(js)
	}

	return true
}

func (app *SimpleWebApp) ensureSessions(w http.ResponseWriter) bool {
	if app.sessions == nil {
		app.HandleError(w, errors.New("session management not configured"))
		return false
	}
	return true
}

// --------------------------------

type CallbackHandler struct {
	state *SimpleWebApp
}

func (h *CallbackHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !h.state.ensureSessions(w) {
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	ctx, span := trace.StartSpan(ctx, r.URL.Path)
	defer span.End()

	session, err := h.state.sessions.Get(r, true)
	if h.state.HandleError(w, err, "getting session") {
		return
	}

	if r.URL.Query().Get("state") != session.Data["state"] {
		http.Error(w, "Invalid state parameter", http.StatusBadRequest)
		return
	}

	token, err := h.state.authConfig.Exchange(ctx, r.URL.Query().Get("code"))
	if err != nil {
		log.Printf("no token found: %v", err)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		http.Error(w, "No id_token field in oauth2 token.", http.StatusInternalServerError)
		return
	}

	p, err := h.state.NewAuthProvder(ctx)

	idToken, err := p.Verifier(h.state.authOIConfig).Verify(ctx, rawIDToken)

	if err != nil {
		http.Error(w, "Failed to verify ID Token: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Getting now the userInfo
	var profile map[string]interface{}
	if err := idToken.Claims(&profile); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	session.Data["id_token"] = rawIDToken
	session.Data["access_token"] = token.AccessToken
	session.Data["profile"] = profile

	backto, _ := session.Data["backto"].(string)
	if len(backto) == 0 {
		backto = "/"
	}

	session.Data["backto"] = ""
	err = session.Save(ctx, r, w)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, backto, http.StatusSeeOther)

}

// --------------------------------

type LoginHandler struct {
	state *SimpleWebApp
}

func (h *LoginHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !h.state.ensureSessions(w) {
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	ctx, span := trace.StartSpan(ctx, r.URL.Path)
	defer span.End()

	// Generate random state
	b := make([]byte, 32)
	_, err := rand.Read(b)
	if h.state.HandleError(w, err, "error getting random number") {
		return
	}
	state := base64.StdEncoding.EncodeToString(b)

	session, err := h.state.sessions.Get(r, true)
	if h.state.HandleError(w, err, "error getting session") {
		return
	}
	session.Data["state"] = state

	if r.FormValue("backto") != "" {
		session.Data["backto"] = r.FormValue("backto")
	}
	if session.Data["backto"] == "" {
		session.Data["backto"] = r.Header.Get("Referer")
	}
	err = session.Save(ctx, r, w)
	if h.state.HandleError(w, err, "error saving session") {
		return
	}

	http.Redirect(w, r, h.state.authConfig.AuthCodeURL(state), http.StatusTemporaryRedirect)
}

// --------------------------------

type LogoutHandler struct {
	state *SimpleWebApp
}

func (h *LogoutHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !h.state.ensureSessions(w) {
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	ctx, span := trace.StartSpan(ctx, r.URL.Path)
	defer span.End()

	logoutUrl, err := url.Parse(h.state.config.auth0Domain)
	if h.state.HandleError(w, err, "internal config error parsing domain") {
		return
	}

	logoutUrl.Path = "/v2/logout"
	parameters := url.Values{}

	parameters.Add("returnTo", h.state.config.webRoot)
	parameters.Add("client_id", h.state.config.auth0ClientId)
	logoutUrl.RawQuery = parameters.Encode()

	h.state.sessions.DeleteSession(ctx, r, w)
	http.Redirect(w, r, logoutUrl.String(), http.StatusTemporaryRedirect)
}

// -------------------------

type TemplateHandler interface {
	// return (template name, thing to pass to template, error)
	Serve(r *http.Request, user UserInfo) (*Template, interface{}, error)
}

type TemplateHandlerFunc func(r *http.Request, user UserInfo) (*Template, interface{}, error)

func (f TemplateHandlerFunc) Serve(r *http.Request, user UserInfo) (*Template, interface{}, error) {
	return f(r, user)
}

type Template struct {
	named  string
	direct *template.Template
}

func NamedTemplate(called string) *Template {
	return &Template{named: called}
}

func DirectTemplate(t *template.Template) *Template {
	return &Template{direct: t}
}

type TemplateMiddleware struct {
	App           *SimpleWebApp
	Handler       TemplateHandler
	RequiresLogin bool
}

func (tm *TemplateMiddleware) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if tm.App.config.webRoot != "" && r.Host != "" && r.Host != tm.App.webRootURL.Host {
		http.Redirect(w, r, tm.App.config.webRoot, http.StatusTemporaryRedirect)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	ctx, span := trace.StartSpan(ctx, r.URL.Path)
	defer span.End()

	r = r.WithContext(ctx)

	user, err := tm.App.GetLoggedInUserInfo(r)
	if tm.App.HandleError(w, err) {
		return
	}

	if tm.RequiresLogin && !user.LoggedIn {
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return
	}

	if user.LoggedIn {
		span.Annotatef(nil, "logged in user: %s", user.GetEmail())
	}

	t, data, err := tm.Handler.Serve(r, user)
	if tm.App.HandleError(w, err) {
		return
	}

	gt := t.direct
	if gt == nil {
		gt, err = tm.App.LookupTemplate(t.named)
		if tm.App.HandleError(w, err) {
			return
		}
	}

	tm.App.HandleError(w, gt.Execute(w, data))
}

// -------------------------

// TODO(erd): find a way to merge or reduce code with TemplateHandler
type APIHandler interface {
	// return (result, error)
	ServeAPI(r *http.Request, user UserInfo) (interface{}, error)
}

// TODO(erd): find a way to merge or reduce code with TemplateMiddleware
type APIMiddleware struct {
	App     *SimpleWebApp
	Handler APIHandler
}

func (am *APIMiddleware) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	ctx, span := trace.StartSpan(ctx, r.URL.Path)
	defer span.End()

	r = r.WithContext(ctx)

	user, err := am.App.GetLoggedInUserInfo(r)
	if am.App.HandleAPIError(w, err, nil) {
		return
	}

	if user.LoggedIn {
		span.Annotatef(nil, "logged in user: %s", user.GetEmail())
	}

	data, err := am.Handler.ServeAPI(r, user)
	if am.App.HandleAPIError(w, err, data) {
		return
	}

	js, err := json.Marshal(data)
	if am.App.HandleAPIError(w, err, nil) {
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(js)
}
