package api

import (
	"crypto/sha256"
	"crypto/subtle"
	"net/http"
	"strings"
)

// requireAPIKey deja pasar solo las peticiones con "Authorization: Bearer <key>".
//
// La comparación es en tiempo constante: con un == normal, la respuesta tarda un poco
// más cuantos más caracteres iniciales coinciden, y un atacante podría adivinar la clave
// carácter a carácter midiendo tiempos. Se comparan los hashes para que tampoco se
// filtre la longitud de la clave.
func requireAPIKey(key string, next http.Handler) http.Handler {
	want := sha256.Sum256([]byte(key))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got, ok := bearerToken(r)
		gotSum := sha256.Sum256([]byte(got))
		if !ok || subtle.ConstantTimeCompare(gotSum[:], want[:]) != 1 {
			w.Header().Set("WWW-Authenticate", `Bearer realm="mini-siem"`)
			writeError(w, http.StatusUnauthorized, "API key inválida o ausente")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func bearerToken(r *http.Request) (string, bool) {
	scheme, token, ok := strings.Cut(r.Header.Get("Authorization"), " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") || token == "" {
		return "", false
	}
	return token, true
}
