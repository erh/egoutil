package egoutil

import (
	"encoding/hex"
	"fmt"
	"regexp"
	"sync"

	"go.opencensus.io/trace"
)

type mySpanInfo struct {
	toPrint string
	id      string
}

type NiceLoggingSpanExporter struct {
	mu       sync.Mutex
	children map[string][]mySpanInfo
}

func NewNiceLoggingSpanExporter() *NiceLoggingSpanExporter {
	return &NiceLoggingSpanExporter{children: map[string][]mySpanInfo{}}
}

var reZero = regexp.MustCompile(`^0+$`)

func (e *NiceLoggingSpanExporter) printTree(root string, padding string) {
	e.mu.Lock()
	defer e.mu.Unlock()

	for _, s := range e.children[root] {
		fmt.Printf("%s %s\n", padding, s.toPrint)
		e.printTree(s.id, padding+"  ")
	}
	delete(e.children, root)
}

func (e *NiceLoggingSpanExporter) ExportSpan(s *trace.SpanData) {
	e.mu.Lock()
	defer e.mu.Unlock()

	length := (s.EndTime.UnixNano() - s.StartTime.UnixNano()) / (1000 * 1000)
	myinfo := fmt.Sprintf("%s %d ms", s.Name, length)

	if s.Annotations != nil {
		for _, a := range s.Annotations {
			myinfo = myinfo + " " + a.Message
		}
	}

	spanID := hex.EncodeToString(s.SpanID[:])
	parentSpanID := hex.EncodeToString(s.ParentSpanID[:])

	if !reZero.MatchString(parentSpanID) {
		lst := append(e.children[parentSpanID], mySpanInfo{myinfo, spanID})
		e.children[parentSpanID] = lst
		return
	}

	// i'm the top of the tree, go me
	fmt.Println(myinfo)
	e.printTree(hex.EncodeToString(s.SpanContext.SpanID[:]), "  ")
}
