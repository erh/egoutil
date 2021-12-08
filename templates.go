package egoutil

import (
	"context"
	"embed"
	"fmt"
	"html/template"
	"io/fs"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Masterminds/sprig"
)

type TemplateManager interface {
	LookupTemplate(name string) (*template.Template, error)
}

func lookupTemplate(main *template.Template, name string) (*template.Template, error) {
	t := main.Lookup(name)
	if t == nil {
		return nil, fmt.Errorf("cannot find template %s", name)
	}
	return t, nil
}

type embedTM struct {
	cachedTemplates *template.Template
}

func (tm *embedTM) LookupTemplate(name string) (*template.Template, error) {
	return lookupTemplate(tm.cachedTemplates, name)
}

func NewTemplateManagerEmbed(fs *embed.FS, srcDir string) (TemplateManager, error) {
	files, err := fs.ReadDir(srcDir)
	if err != nil {
		return nil, err
	}

	newFiles := fixFiles(files, srcDir)

	ts, err := baseTemplate().ParseFS(fs, newFiles...)
	if err != nil {
		return nil, fmt.Errorf("error initializing templates from embedded filesystem: %w", err)
	}
	return &embedTM{ts}, nil
}

type fsTM struct {
	srcDir string
}

func (tm *fsTM) LookupTemplate(name string) (*template.Template, error) {
	files, err := os.ReadDir(tm.srcDir)
	if err != nil {
		return nil, err
	}

	newFiles := fixFiles(files, tm.srcDir)

	main, err := baseTemplate().ParseFiles(newFiles...)
	if err != nil {
		return nil, err
	}
	return lookupTemplate(main, name)
}

func NewTemplateManagerFS(srcDir string) (TemplateManager, error) {
	return &fsTM{srcDir}, nil
}

// -------------------------

type TemplateHandler interface {
	// return (template name, thing to pass to template, error)
	Serve(w http.ResponseWriter, r *http.Request) (*Template, interface{}, error)
}

type TemplateHandlerFunc func(w http.ResponseWriter, r *http.Request) (*Template, interface{}, error)

func (f TemplateHandlerFunc) Serve(w http.ResponseWriter, r *http.Request) (*Template, interface{}, error) {
	return f(w, r)
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
	Templates TemplateManager
	Handler   TemplateHandler
}

func (tm *TemplateMiddleware) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	r = r.WithContext(ctx)

	t, data, err := tm.Handler.Serve(w, r)
	if HandleError(w, err) {
		return
	}

	gt := t.direct
	if gt == nil {
		gt, err = tm.Templates.LookupTemplate(t.named)
		if HandleError(w, err) {
			return
		}
	}

	HandleError(w, gt.Execute(w, data))
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

func baseTemplate() *template.Template {
	return template.New("app").Funcs(sprig.FuncMap())
}

type VerifyHost struct {
	WebRoot string
	Host    string
	Handler http.Handler
}

func NewVerifyHost(root string, h http.Handler) *VerifyHost {
	u, err := url.Parse(root)
	if err != nil {
		panic(err)
	}
	return &VerifyHost{root, u.Host, h}
}

func (vh *VerifyHost) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Host != "" && r.Host != vh.Host {
		http.Redirect(w, r, vh.WebRoot, http.StatusTemporaryRedirect)
	} else {
		vh.Handler.ServeHTTP(w, r)
	}
}
