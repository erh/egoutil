package egoutil

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/oauth2"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"

	oidc "github.com/coreos/go-oidc"

	"go.opencensus.io/trace"

	"github.com/fsnotify/fsnotify"
)

type UserInfo struct {
	LoggedIn   bool
	Properties map[string]interface{}
}

func (u *UserInfo) GetEmail() string {
	return u.Properties["email"].(string)
}

func (u *UserInfo) GetEmailVerified() bool {
	return u.Properties["email_verified"].(bool)
}

// ----

type SimpleWebAppConfig struct {
	templateDir string
	mongoURL    string

	auth0Domain   string
	auth0ClientId string
	auth0Secret   string

	webRoot string
}

func NewSimpleWebAppConfig() *SimpleWebAppConfig {
	return &SimpleWebAppConfig{
		templateDir: "templates",
		mongoURL:    "mongodb://localhost",
		webRoot:     "http://localhost:8080",
	}
}

func (c *SimpleWebAppConfig) SetTemplateDir(dir string) *SimpleWebAppConfig {
	c.templateDir = dir
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
	config *SimpleWebAppConfig

	allTemplates *template.Template

	MongoClient *mongo.Client

	Mux *http.ServeMux

	sessions *SessionManager

	authOIConfig *oidc.Config
	authConfig   oauth2.Config
}

func NewSimpleWebApp(ctx context.Context, cfg *SimpleWebAppConfig) (*SimpleWebApp, error) {
	a := &SimpleWebApp{}
	a.config = cfg

	// templates
	err := a.initTemplates()
	if err != nil {
		return nil, err
	}

	// mongo
	a.MongoClient, err = mongo.Connect(ctx, options.Client().ApplyURI(cfg.mongoURL))
	if err != nil {
		return nil, err
	}

	// muxer
	a.Mux = http.NewServeMux()

	// init session store
	a.sessions = NewSessionManager(&MongoDBSessionStore{a.MongoClient.Database("web").Collection("sessions"), nil})

	// auth0
	err = a.initAuth0(ctx)
	if err != nil {
		return nil, err
	}

	return a, nil
}

func (app *SimpleWebApp) initAuth0(ctx context.Context) error {
	if len(app.config.auth0Domain) == 0 {
		return nil
	}

	// init auth
	app.authOIConfig = &oidc.Config{
		ClientID: app.config.auth0ClientId,
	}

	p, err := app.NewAuthProvder(ctx)
	if err != nil {
		return err
	}

	app.authConfig = oauth2.Config{
		ClientID:     app.config.auth0ClientId,
		ClientSecret: app.config.auth0Secret,
		RedirectURL:  app.config.webRoot + "/callback",
		Endpoint:     p.Endpoint(),
		Scopes:       []string{oidc.ScopeOpenID, "profile", "email"},
	}

	app.Mux.Handle("/callback", &CallbackHandler{app})
	app.Mux.Handle("/login", &LoginHandler{app})
	app.Mux.Handle("/logout", &LogoutHandler{app})

	return nil
}

func (app *SimpleWebApp) GetLoggedInUserInfo(ctx context.Context, r *http.Request) (UserInfo, error) {
	ui := UserInfo{LoggedIn: false, Properties: map[string]interface{}{"email": ""}}

	session, err := app.sessions.Get(ctx, r, false)
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

	return ui, nil
}

func (app *SimpleWebApp) NewAuthProvder(ctx context.Context) (*oidc.Provider, error) {
	p, err := oidc.NewProvider(ctx, app.config.auth0Domain)
	if err != nil {
		return nil, fmt.Errorf("failed to get provider: %v", err)
	}
	return p, nil
}

func (app *SimpleWebApp) initTemplates() error {
	files, err := filepath.Glob(app.config.templateDir + "/*.html")
	if err != nil {
		return err
	}

	newFiles := []string{}
	for _, x := range files {
		if strings.ContainsAny(x, "#") {
			continue
		}
		newFiles = append(newFiles, x)
	}

	// only assign after we check for errors in case we're reloading
	foo, err := template.ParseFiles(newFiles...)
	if err == nil {
		app.allTemplates = foo
	}
	return err
}

func (app *SimpleWebApp) LookupTemplate(name string) *template.Template {
	return app.allTemplates.Lookup(name)
}

func (app *SimpleWebApp) ReloadTemplateThread() {
	// creates a new file watcher
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		log.Fatal(err)
	}
	defer watcher.Close()

	// out of the box fsnotify can watch a single file, or a single directory
	err = watcher.Add(app.config.templateDir)
	if err != nil {
		log.Fatal(err)
	}

	for {
		select {
		// watch for events
		case <-watcher.Events:
			err := app.initTemplates()
			if err != nil {
				log.Printf("error releading templates: %s\n", err)
			} else {
				log.Print("reloaded templates")
			}

		case err := <-watcher.Errors:
			log.Fatal(err)
		}
	}

}

func (app *SimpleWebApp) HandleError(w http.ResponseWriter, err error, context ...string) bool {
	if err == nil {
		return false
	}
	w.WriteHeader(500)
	for _, x := range context {
		w.Write([]byte(x))
		w.Write([]byte{'\n'})
	}
	w.Write([]byte(err.Error()))
	w.Write([]byte{'\n'})
	log.Println(err)
	return true
}

// --------------------------------

type CallbackHandler struct {
	state *SimpleWebApp
}

func (h *CallbackHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	ctx, span := trace.StartSpan(ctx, r.URL.Path)
	defer span.End()

	session, err := h.state.sessions.Get(ctx, r, true)
	if h.state.HandleError(w, err, "gettion session") {
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
	err = session.Save(ctx, r, w)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Redirect to logged in page
	http.Redirect(w, r, "/", http.StatusSeeOther)

}

// --------------------------------

type LoginHandler struct {
	state *SimpleWebApp
}

func (h *LoginHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
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

	session, err := h.state.sessions.Get(ctx, r, true)
	if h.state.HandleError(w, err, "error getting session") {
		return
	}
	session.Data["state"] = state
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
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
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
