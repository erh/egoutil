package egoutil

import (
	"context"
	"io"
	"log"
	"net/http"
	"net/url"

	"go.uber.org/multierr"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.mongodb.org/mongo-driver/mongo/readpref"

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
	mongoURL string

	auth0Domain   string
	auth0ClientId string
	auth0Secret   string

	webRoot string
}

func NewSimpleWebAppConfig() *SimpleWebAppConfig {
	return &SimpleWebAppConfig{}
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
