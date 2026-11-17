// Package web sirve el dashboard: una página estática que consulta la API con fetch.
package web

import (
	_ "embed"
	"net/http"
)

//go:embed index.html
var indexHTML []byte

// Dashboard sirve la página. Va embebida en el binario: no hay archivos que copiar.
func Dashboard(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	// La página no carga nada externo: si algo inyectara un <script> de otro origen,
	// el navegador lo bloquearía.
	w.Header().Set("Content-Security-Policy",
		"default-src 'none'; script-src 'self' 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; img-src 'self' data:")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Write(indexHTML)
}
