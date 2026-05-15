// splitter.go - Trasforma un sorgente monolitico in package modulari completi.
// Uso: go run splitter.go myminivault.go

package main

import (
	"bytes"
	"fmt"
	"go/ast"
	"go/format"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
)

type module struct {
	Name string
	Path string
	Pred func(name string, decl ast.Node) bool
}

var modules = []module{
	{
		Name: "config", Path: "internal/config",
		Pred: func(name string, _ ast.Node) bool {
			consts := []string{
				"vaultFile", "configFile", "logFile",
				"tokenRegistry", "tokenKeyFile",
				"sharedTokenVault", "saltSize", "vaultVersion",
			}
			for _, c := range consts {
				if name == c {
					return true
				}
			}
			return name == "Config" || name == "loadConfig" || name == "showConfig"
		},
	},
	{
		Name: "crypto", Path: "internal/crypto",
		Pred: func(name string, _ ast.Node) bool {
			set := map[string]bool{
				"deriveKey": true, "encrypt": true, "decrypt": true,
				"generateRandom": true,
			}
			return set[name]
		},
	},
	{
		// ⭐ AGGIORNATO: Tutti i tipi e funzioni core del vault insieme
		Name: "vault", Path: "internal/vault",
		Pred: func(name string, _ ast.Node) bool {
			vaultItems := map[string]bool{
				// Tipi vault originali
				"ExtendedVault": true,
				"VaultMetadata": true,
				"RecoveryData":  true,
				// ⭐ AGGIUNGI I TIPI TOKEN QUI (per evitare undefined)
				"TokenManager":  true,
				"AccessToken":   true,
				"TokenRegistry": true,
				// Funzioni vault core
				"loadAndDecryptExtendedVault": true,
				"saveExtendedVault":           true,
				"saveVaultFileAtomic":         true,
				"tryLoad":                     true,
				"validateKey":                 true,
				"generateRecoveryKey":         true,
				"validateRecoveryKey":         true,
				"setCurrentRecoveryKey":       true,
				"getCurrentRecoveryKey":       true,
				"saveRecoveryFile":            true,
			}
			return vaultItems[name]
		},
	},
	{
		// ⭐ AGGIORNATO: Solo funzioni token, non i tipi (che stanno in vault)
		Name: "token", Path: "internal/token",
		Pred: func(name string, _ ast.Node) bool {
			// Funzioni token ma NON i tipi (per evitare conflitti)
			tokenFunctions := map[string]bool{
				"getOrCreateTokenMasterKey":       true,
				"loadTokenMasterKey":              true,
				"saveTokenMasterKey":              true,
				"cleanupExpiredTokens":            true,
				"executeWithToken":                true,
				"parseAndValidateProductionToken": true,
				"addBase64Padding":                true,
				"loadSharedTokenVault":            true,
				"saveTokenVaultEncrypted":         true,
				"loadVaultFromTokenFileEncrypted": true,
				"saveTokenVaultFileAtomic":        true,
				"loadTokenRegistry":               true,
				"saveTokenRegistry":               true,
				"executeTokenGet":                 true,
				"executeTokenSet":                 true,
				"executeTokenList":                true,
				"executeTokenSearch":              true,
				"matchKeyPattern":                 true,
				"generateShortRandomID":           true,
				"createShortSignedToken":          true,
				"logTokenAccess":                  true,
				"getKeyFromTokenArgs":             true,
				"contains":                        true,
				"syncSharedVaultToMainVault":      true,
				"syncTokenVaultWithMainVault":     true,
			}
			return tokenFunctions[name]
		},
	},
	{
		Name: "commands", Path: "internal/commands",
		Pred: func(name string, decl ast.Node) bool {
			if strings.HasPrefix(name, "handle") ||
				strings.HasPrefix(name, "execute") ||
				name == "showHelp" ||
				name == "showUsage" {
				return true
			}
			return false
		},
	},
}

// Resto delle funzioni rimane identico al tuo...
func extractImports(root *ast.File) []*ast.GenDecl {
	var imports []*ast.GenDecl
	for _, decl := range root.Decls {
		if genDecl, ok := decl.(*ast.GenDecl); ok && genDecl.Tok == token.IMPORT {
			imports = append(imports, genDecl)
		}
	}
	return imports
}

func writePackageHeader(buffer *bytes.Buffer, pkgName string, imports []*ast.GenDecl, fset *token.FileSet) {
	buffer.WriteString(fmt.Sprintf("package %s\n\n", pkgName))

	for _, imp := range imports {
		var tempBuf bytes.Buffer
		format.Node(&tempBuf, fset, imp)
		buffer.Write(tempBuf.Bytes())
		buffer.WriteString("\n")
	}

	if len(imports) > 0 {
		buffer.WriteString("\n")
	}
}

func formatNodeWithNewline(buffer *bytes.Buffer, fset *token.FileSet, n ast.Node) error {
	var tempBuf bytes.Buffer
	err := format.Node(&tempBuf, fset, n)
	if err != nil {
		return err
	}

	code := tempBuf.String()
	code = strings.ReplaceAll(code, "}func", "}\n\nfunc")
	code = strings.ReplaceAll(code, "}type", "}\n\ntype")
	code = strings.ReplaceAll(code, "}var", "}\n\nvar")
	code = strings.ReplaceAll(code, "}const", "}\n\nconst")

	buffer.WriteString(code)
	buffer.WriteString("\n\n")
	return nil
}

// Main e resto delle funzioni identiche al tuo file...
func main() {
	if len(os.Args) != 2 {
		fmt.Println("uso: go run splitter.go myminivault.go")
		os.Exit(1)
	}

	srcFile := os.Args[1]
	fset := token.NewFileSet()
	root, err := parser.ParseFile(fset, srcFile, nil, parser.ParseComments)
	if err != nil {
		panic(err)
	}

	imports := extractImports(root)
	buffers := map[string]*bytes.Buffer{}
	for _, m := range modules {
		buffers[m.Name] = &bytes.Buffer{}
		writePackageHeader(buffers[m.Name], m.Name, imports, fset)
	}

	ast.Inspect(root, func(n ast.Node) bool {
		switch d := n.(type) {
		case *ast.GenDecl:
			if d.Tok == token.IMPORT {
				return false
			}

			for _, spec := range d.Specs {
				var name string
				switch s := spec.(type) {
				case *ast.TypeSpec:
					name = s.Name.Name
				case *ast.ValueSpec:
					if len(s.Names) > 0 {
						name = s.Names[0].Name
					}
				}

				if name == "" {
					continue
				}

				target := findModule(name, d)
				if target == nil {
					continue
				}

				if err := formatNodeWithNewline(buffers[target.Name], fset, d); err != nil {
					panic(err)
				}

				return false
			}

		case *ast.FuncDecl:
			name := d.Name.Name
			if name == "main" {
				return false
			}

			target := findModule(name, d)
			if target == nil {
				return false
			}

			if err := formatNodeWithNewline(buffers[target.Name], fset, d); err != nil {
				panic(err)
			}

			return false
		}

		return true
	})

	os.MkdirAll("vault", 0o755)
	writeFile("vault/go.mod", gomod())
	writeFile("vault/main.go", mainFile())

	for _, m := range modules {
		dir := filepath.Join("vault", m.Path)
		os.MkdirAll(dir, 0o755)
		path := filepath.Join(dir, m.Name+".go")
		writeFile(path, buffers[m.Name].String())
		fmt.Printf("✅ %s\n", path)
	}

	fmt.Println("✔️ Split completato con import e formattazione corretta")
}

func findModule(name string, decl ast.Node) *module {
	for _, m := range modules {
		if m.Pred(name, decl) {
			return &m
		}
	}
	return nil
}

func writeFile(path, data string) {
	if err := os.WriteFile(path, []byte(data), 0o644); err != nil {
		panic(err)
	}
}

func gomod() string {
	return `module vault

go 1.21

require (
	golang.org/x/crypto v0.14.0
	golang.org/x/term v0.13.0
)
`
}

func mainFile() string {
	return `package main

import "vault/internal/commands"

func main() {
	commands.Dispatch()
}
`
}
