// Command openapi30 rewrites YNAB's OpenAPI 3.1 document as 3.0, which is what
// oapi-codegen can read. The only 3.1 construct the YNAB spec uses is the
// nullable type array (`type: [string, "null"]`), so that is all this rewrites:
// each one becomes 3.0's single type plus `nullable: true`.
//
// The rewrite runs at generate time and its output is committed alongside the
// generated client, so neither building nor testing needs it.
package main

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintln(os.Stderr, "usage: openapi30 <in.yaml> <out.yaml>")
		os.Exit(2)
	}
	in, err := os.ReadFile(os.Args[1])
	check(err)
	var doc yaml.Node
	check(yaml.Unmarshal(in, &doc))
	walk(&doc)
	setVersion(&doc)
	out, err := yaml.Marshal(&doc)
	check(err)
	check(os.WriteFile(os.Args[2], out, 0o644))
}

// walk rewrites every mapping node whose `type` is a sequence containing
// "null". Anything else is left exactly as it was, including key order, so the
// diff against the upstream spec stays readable.
func walk(n *yaml.Node) {
	if n.Kind == yaml.MappingNode {
		for i := 0; i+1 < len(n.Content); i += 2 {
			key, val := n.Content[i], n.Content[i+1]
			if key.Value != "type" || val.Kind != yaml.SequenceNode {
				continue
			}
			var concrete *yaml.Node
			nullable := false
			for _, t := range val.Content {
				if t.Value == "null" {
					nullable = true
				} else {
					concrete = t
				}
			}
			if !nullable || concrete == nil {
				continue
			}
			n.Content[i+1] = concrete
			n.Content = append(n.Content,
				&yaml.Node{Kind: yaml.ScalarNode, Value: "nullable"},
				&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!bool", Value: "true"})
		}
	}
	for _, c := range n.Content {
		walk(c)
	}
}

func setVersion(doc *yaml.Node) {
	if len(doc.Content) == 0 {
		return
	}
	root := doc.Content[0]
	for i := 0; i+1 < len(root.Content); i += 2 {
		if root.Content[i].Value == "openapi" {
			root.Content[i+1].Value = "3.0.3"
			return
		}
	}
}

func check(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
