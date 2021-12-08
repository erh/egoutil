package egoutil

import (
	"context"
	"embed"
	"errors"
	"fmt"
	"html/template"
	"io"
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

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.mongodb.org/mongo-driver/mongo/readpref"

	"go.opencensus.io/trace"
	"goji.io"
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

	auth0State io.Closer
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
	if app.auth0State != nil {
		err = multierr.Combine(err, app.auth0State.Close())
	}
	// mongo driver uses http.DefaultClient with no way to supply our own (like auth0 does).
	http.DefaultClient.CloseIdleConnections()
	return err
}

func (app *SimpleWebApp) initAuth0(ctx context.Context) error {
	if len(app.config.auth0Domain) == 0 {
		return nil
	}

	var err error
	app.auth0State, err = InstallAuth0(
		ctx,
		app.Mux,
		app.sessions,
		Auth0Config{
			Domain:   app.config.auth0Domain,
			ClientID: app.config.auth0ClientId,
			Secret:   app.config.auth0Secret,
			WebRoot:  app.config.webRoot,
		},
	)
	return err
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

// HandleError returns true if there was an error and you should stop
func HandleError(w http.ResponseWriter, err error, context ...string) bool {
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
	if HandleError(w, err) {
		return
	}

	if tm.RequiresLogin && !user.LoggedIn {
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return
	}

	t, data, err := tm.Handler.Serve(r, user)
	if HandleError(w, err) {
		return
	}

	gt := t.direct
	if gt == nil {
		gt, err = tm.App.LookupTemplate(t.named)
		if HandleError(w, err) {
			return
		}
	}

	HandleError(w, gt.Execute(w, data))
}
