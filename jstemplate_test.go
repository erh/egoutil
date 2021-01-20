package egoutil

import (
	"bytes"
	"html/template"
	"io/ioutil"
	"testing"

	"github.com/robertkrimen/otto"
)

func evalToString(t *template.Template, data interface{}) string {
	buf := bytes.NewBufferString("")
	err := t.Execute(buf, data)
	if err != nil {
		panic(err)
	}
	return buf.String()
}

func compareTemplates(t *testing.T, code string, data interface{}) {
	tt, err := template.New("foo").Parse(code)
	if err != nil {
		t.Error(err)
	}

	x := nodeToJSON(tt.Tree.Root)

	raw, err := ioutil.ReadFile("jstemplate.js")
	if err != nil {
		t.Error(err)
	}

	vm := otto.New()
	_, err = vm.Run(string(raw))
	if err != nil {
		t.Error(err)
	}

	vm.Set("theTemplate", x)
	vm.Set("data", data)

	resJS, err := vm.Run(`evaluateTemplate(theTemplate, data)`)
	if err != nil {
		t.Error(err)
	}

	resGO := evalToString(tt, data)

	if resJS.String() != resGO {
		t.Errorf("results don't match\n%s\n%s\n", resJS.String(), resGO)
	}

}

func TestBasic1(t *testing.T) {
	code := "a{{ .Foo }}{{ .Bar.Foo }}b"
	data := map[string]interface{}{}
	data["Foo"] = 517
	data["Bar"] = map[string]interface{}{"Foo": 715}

	compareTemplates(t, code, data)
}

func TestIf1(t *testing.T) {
	code := "a{{ if .x }}5{{end}}b"
	data := map[string]interface{}{}

	data["x"] = true
	compareTemplates(t, code, data)

	data["x"] = false
	compareTemplates(t, code, data)
}

func TestIf2(t *testing.T) {
	code := "a{{ if .x }}5{{else}}17{{end}}b"
	data := map[string]interface{}{}

	data["x"] = true
	compareTemplates(t, code, data)

	data["x"] = false
	compareTemplates(t, code, data)
}

func TestRange1(t *testing.T) {
	code := "a{{ range $x := .things }}a{{ $x }}b{{end}}b"
	data := map[string]interface{}{}
	data["things"] = []int{5, 17}

	compareTemplates(t, code, data)
}

func TestRange2(t *testing.T) {
	code := "a{{ range $x := .things }}a{{ $x.c }}b{{end}}b"
	data := map[string]interface{}{}
	data["things"] = []map[string]int{{"c": 5}, {"c": 17}}

	compareTemplates(t, code, data)
}
