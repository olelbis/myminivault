package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strings"
	"time"
)

type goModule struct {
	Path    string
	Version string
	Sum     string
	Main    bool
	Replace *goModule
}

type spdxDocument struct {
	SPDXID        string         `json:"SPDXID"`
	SPDXVersion   string         `json:"spdxVersion"`
	CreationInfo  creationInfo   `json:"creationInfo"`
	DataLicense   string         `json:"dataLicense"`
	DocumentName  string         `json:"name"`
	DocumentNS    string         `json:"documentNamespace"`
	Packages      []spdxPackage  `json:"packages"`
	Relationships []relationship `json:"relationships"`
}

type creationInfo struct {
	Created  string   `json:"created"`
	Creators []string `json:"creators"`
}

type spdxPackage struct {
	SPDXID                  string            `json:"SPDXID"`
	Name                    string            `json:"name"`
	VersionInfo             string            `json:"versionInfo,omitempty"`
	DownloadLocation        string            `json:"downloadLocation"`
	FilesAnalyzed           bool              `json:"filesAnalyzed"`
	LicenseConcluded        string            `json:"licenseConcluded"`
	LicenseDeclared         string            `json:"licenseDeclared"`
	CopyrightText           string            `json:"copyrightText"`
	ExternalRefs            []externalRef     `json:"externalRefs,omitempty"`
	PackageVerificationCode *verificationCode `json:"packageVerificationCode,omitempty"`
}

type verificationCode struct {
	Value string `json:"packageVerificationCodeValue"`
}

type externalRef struct {
	Category string `json:"referenceCategory"`
	Type     string `json:"referenceType"`
	Locator  string `json:"referenceLocator"`
}

type relationship struct {
	SPDXElementID      string `json:"spdxElementId"`
	RelationshipType   string `json:"relationshipType"`
	RelatedSPDXElement string `json:"relatedSpdxElement"`
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "sbom: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	modules, err := listModules()
	if err != nil {
		return err
	}
	if len(modules) == 0 {
		return fmt.Errorf("no Go modules found")
	}

	tag := os.Getenv("TAG_NAME")
	if tag == "" {
		tag = "dev"
	}

	doc := spdxDocument{
		SPDXID:      "SPDXRef-DOCUMENT",
		SPDXVersion: "SPDX-2.3",
		CreationInfo: creationInfo{
			Created:  time.Now().UTC().Format(time.RFC3339),
			Creators: []string{"Tool: myminivault tools/sbom"},
		},
		DataLicense:  "CC0-1.0",
		DocumentName: "myminivault-" + tag,
		DocumentNS:   fmt.Sprintf("https://github.com/olelbis/myminivault/sbom/%s/%s", tag, digest(tag)),
	}

	sort.Slice(modules, func(i, j int) bool {
		return modules[i].Path < modules[j].Path
	})

	rootID := ""
	for _, mod := range modules {
		pkg := packageFromModule(mod)
		if mod.Main {
			rootID = pkg.SPDXID
		}
		doc.Packages = append(doc.Packages, pkg)
	}
	if rootID == "" {
		rootID = doc.Packages[0].SPDXID
	}
	doc.Relationships = append(doc.Relationships, relationship{
		SPDXElementID:      "SPDXRef-DOCUMENT",
		RelationshipType:   "DESCRIBES",
		RelatedSPDXElement: rootID,
	})
	for _, pkg := range doc.Packages {
		if pkg.SPDXID == rootID {
			continue
		}
		doc.Relationships = append(doc.Relationships, relationship{
			SPDXElementID:      rootID,
			RelationshipType:   "DEPENDS_ON",
			RelatedSPDXElement: pkg.SPDXID,
		})
	}

	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(doc)
}

func listModules() ([]goModule, error) {
	cmd := exec.Command("go", "list", "-m", "-json", "all")
	out, err := cmd.Output()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			return nil, fmt.Errorf("go list modules: %s", strings.TrimSpace(string(exitErr.Stderr)))
		}
		return nil, fmt.Errorf("go list modules: %w", err)
	}

	decoder := json.NewDecoder(bytes.NewReader(out))
	var modules []goModule
	for decoder.More() {
		var mod goModule
		if err := decoder.Decode(&mod); err != nil {
			return nil, fmt.Errorf("decode module metadata: %w", err)
		}
		modules = append(modules, mod)
	}
	return modules, nil
}

func packageFromModule(mod goModule) spdxPackage {
	version := mod.Version
	if version == "" {
		version = "local"
	}
	pkg := spdxPackage{
		SPDXID:           "SPDXRef-Package-" + digest(mod.Path+"@"+version),
		Name:             mod.Path,
		VersionInfo:      version,
		DownloadLocation: "NOASSERTION",
		FilesAnalyzed:    false,
		LicenseConcluded: "NOASSERTION",
		LicenseDeclared:  "NOASSERTION",
		CopyrightText:    "NOASSERTION",
	}
	if mod.Sum != "" {
		pkg.PackageVerificationCode = &verificationCode{Value: digest(mod.Sum)}
	}
	if !mod.Main {
		pkg.ExternalRefs = append(pkg.ExternalRefs, externalRef{
			Category: "PACKAGE-MANAGER",
			Type:     "purl",
			Locator:  packageURL(mod),
		})
	}
	return pkg
}

func packageURL(mod goModule) string {
	version := mod.Version
	if mod.Replace != nil && mod.Replace.Version != "" {
		version = mod.Replace.Version
	}
	if version == "" {
		return "pkg:golang/" + mod.Path
	}
	return "pkg:golang/" + mod.Path + "@" + version
}

func digest(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])[:16]
}
