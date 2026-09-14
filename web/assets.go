// Package web holds the templates and static files, embedded into the binary.
//
// Embedding keeps deployment to a single file: there is no asset directory to
// keep in step with the executable, and no chance of a half-updated deploy
// serving new HTML against old JavaScript.
package web

import "embed"

//go:embed templates/*.html static/* i18n/*.json
var Assets embed.FS
