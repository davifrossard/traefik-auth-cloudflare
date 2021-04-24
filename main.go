package main

import (
	"context"
	"fmt"
	"strings"
	"log"
	"net/http"
	"regexp"
	"os"

	"github.com/coreos/go-oidc"
	flag "github.com/spf13/pflag"
)

// Claims stores the values we want to extract from the JWT as JSON
type Claims struct {
	Email string `json:"email"`
}

var (
	// default flag values
	authDomain = ""
	address    = ""
	port       = 80

	// jwt signing keys
	keySet oidc.KeySet
)

func init() {

	// parse flags
	flag.StringVar(&authDomain, "auth-domain", authDomain, "authentication domain (https://foo.cloudflareaccess.com)")
	flag.IntVar(&port, "port", port, "http port to listen on")
	flag.StringVar(&address, "address", address, "http address to listen on (leave empty to listen on all interfaces)")
	flag.Parse()

	// --auth-domain is required
	if authDomain == "" {
		fmt.Println("ERROR: Please set --auth-domain to the authorization domain you configured on cloudflare. Should be like `https://foo.cloudflareaccess.com`")
		flag.Usage()
		os.Exit(1)
	}

	// configure keyset
	certsURL := fmt.Sprintf("%s/cdn-cgi/access/certs", authDomain)
	keySet = oidc.NewRemoteKeySet(context.TODO(), certsURL)

}

func main() {
	addr := fmt.Sprintf("%s:%d", address, port)
	http.HandleFunc("/", authHandler)
	log.Fatalln(http.ListenAndServe(addr, nil))
}

func string_to_envkey(lookup string) string {
	re := regexp.MustCompile(`\W`)
	return strings.ToUpper(re.ReplaceAllString(lookup, "_"))
}

func find_env_key(request_domain string, request_resource string) (string, bool) {
	parts := strings.Split(request_resource, "/")

	audience := ""
	found := false

	for i:=0; i < len(parts); i++ {
		thisquery := strings.Trim(request_domain + "/" + strings.Join(parts[:i], "/"), "/")
		env_key := string_to_envkey(thisquery)
		this_audience, this_found := os.LookupEnv(env_key)
		if this_found {
			audience, found = this_audience, this_found
		}
    }

	return audience, found
}

func authHandler(w http.ResponseWriter, r *http.Request) {

	request_domain := r.Header.Get("X-Forwarded-Host")
	request_resource := strings.Trim(r.Header.Get("X-Forwarded-Uri"), "/")
	// request_ip := r.Header.Get("X-Forwarded-For")
	audience, has_audience := find_env_key(request_domain, request_resource)

	if !has_audience {
		log.Printf("Audience not found for request %s/%s.", request_domain, request_resource)
		ix := strings.Index(request_domain, ".")
		request_domain = request_domain[ix+1:]
		log.Printf("Falling back to %s", request_domain)
		audience_, has_audience := os.LookupEnv(string_to_envkey(request_domain))
		if !has_audience {
			write(w, http.StatusBadRequest, "(400) Bad Request")
			return
		}
		audience = audience_
	}

	// Configure verifier
	config := &oidc.Config{
		ClientID: audience,
	}
	verifier := oidc.NewVerifier(authDomain, keySet, config)

	// Make sure that the incoming request has our token header
	//  Could also look in the cookies for CF_AUTHORIZATION
	accessJWT := r.Header.Get("Cf-Access-Jwt-Assertion")
	if accessJWT == "" {
		log.Printf("No token on request for %s", request_domain)

		_, bypass := os.LookupEnv(string_to_envkey(request_domain) + "_BYPASS")
		if bypass {
			log.Printf("Bypassing checks for %s", request_domain)
			write(w, http.StatusOK, "OK!")
			return
		}

		write(w, http.StatusUnauthorized, "No token on the request")
		return
	}

	// Verify the access token
	ctx := r.Context()
	idToken, err := verifier.Verify(ctx, accessJWT)
	if err != nil {
		log.Printf("Invalid token on request for %s", request_domain)
		write(w, http.StatusUnauthorized, fmt.Sprintf("Invalid token: %s", err.Error()))
		return
	}

	// parse the claims
	claims := Claims{}
	err = idToken.Claims(&claims)
	if err != nil {
		log.Printf("Invalid claims on request for %s", request_domain)
		write(w, http.StatusUnauthorized, fmt.Sprintf("Invalid claims: %s", err.Error()))
		return
	}

	// email is required in claims
	if claims.Email == "" {
		log.Printf("Missing email claim on request for %s", request_domain)
		write(w, http.StatusUnauthorized, "No email in JWT claims")
		return
	}

	log.Printf("Authorized request for %s (%s)", request_domain, claims.Email)

	// Request is good to go
	w.Header().Set("X-Auth-User", claims.Email)
	write(w, http.StatusOK, "OK!")

}

func write(w http.ResponseWriter, status int, body string) {
	w.WriteHeader(status)
	_, err := w.Write([]byte(body))
	if err != nil {
		log.Printf("Error writing body: %s\n", err)
	}
}
