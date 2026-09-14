package server

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httputil"
	"reflect"
	"unsafe"

	"github.com/jcmturner/gokrb5/v8/client"
	"github.com/jcmturner/gokrb5/v8/spnego"
	log "github.com/sirupsen/logrus"
	ipa "github.com/ubccr/goipa"
)

// FreeIPA client factories. Package-level vars so tests can point them at a
// fake FreeIPA server; production always uses the goipa defaults.
var (
	// HTTP client for direct JSON-RPC calls (passkeys, user_status, ...)
	ipaRPCHTTPClient = http.DefaultClient

	newIPAClient            = ipa.NewDefaultClient
	newIPAClientWithSession = ipa.NewDefaultClientWithSession
	ipaKeytabLogin          = func(c *ipa.Client, keytab, username string) error {
		return c.LoginWithKeytab(keytab, username)
	}
)

func ipaRPC(client *ipa.Client, method string, params []string, options ipa.Options) (*ipa.Response, error) {
	if len(client.SessionID()) > 0 {
		return ipaSessionRPC(client, method, params, options)
	}

	return ipaKerberosRPC(client, method, params, options)
}

func ipaSessionRPC(client *ipa.Client, method string, params []string, options ipa.Options) (*ipa.Response, error) {
	if client.SessionID() == "" {
		return nil, fmt.Errorf("session RPC requires an authenticated FreeIPA session")
	}

	b, err := marshalPayload(method, params, options)
	if err != nil {
		return nil, err
	}

	req, err := prepareRequest(client, b)
	if err != nil {
		return nil, err
	}

	// authentication
	req.Header.Set("Cookie", fmt.Sprintf("ipa_session=%s", client.SessionID()))

	res, err := ipaRPCHTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("IPA session RPC failed with HTTP status code: %d", res.StatusCode)
	}

	return unmarshalIPAResponse(res)
}

func ipaKerberosRPC(c *ipa.Client, method string, params []string, options ipa.Options) (*ipa.Response, error) {
	krbClient := extractKerberosClient(c)
	if krbClient == nil {
		return nil, fmt.Errorf("Kerberos RPC requires an authenticated FreeIPA session")
	}

	b, err := marshalPayload(method, params, options)
	if err != nil {
		return nil, err
	}

	req, err := prepareRequest(c, b)
	if err != nil {
		return nil, err
	}

	// authentication
	spnego.SetSPNEGOHeader(krbClient, req, "")

	if log.IsLevelEnabled(log.TraceLevel) {
		dump, _ := httputil.DumpRequestOut(req, true)
		log.Tracef("FreeIPA RPC request: %s", dump)
	}

	res, err := ipaRPCHTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("IPA Kerberos RPC failed with HTTP status code: %d", res.StatusCode)
	}

	return unmarshalIPAResponse(res)
}

func marshalPayload(method string, params []string, options ipa.Options) ([]byte, error) {
	if options == nil {
		options = ipa.Options{}
	}

	options["version"] = ipa.IpaClientVersion

	data := []any{
		params,
		options,
	}

	payload := ipa.Options{
		"id":     0,
		"method": method,
		"params": data,
	}

	return json.Marshal(payload)
}

func prepareRequest(c *ipa.Client, payload []byte) (*http.Request, error) {
	var url string
	if len(c.SessionID()) > 0 {
		url = fmt.Sprintf("https://%s/ipa/session/json", c.Host())
	} else {
		url = fmt.Sprintf("https://%s/ipa/json", c.Host())
	}

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(payload))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Referer", fmt.Sprintf("https://%s/ipa/xml", c.Host()))

	return req, nil
}

func unmarshalIPAResponse(res *http.Response) (*ipa.Response, error) {
	rawJSON, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}

	var ipaRes ipa.Response
	if err := json.Unmarshal(rawJSON, &ipaRes); err != nil {
		return nil, err
	}

	if ipaRes.Error != nil {
		return nil, ipaRes.Error
	}

	return &ipaRes, nil
}

func extractKerberosClient(c *ipa.Client) *client.Client {
	// magicke moste evile
	cr := reflect.ValueOf(c)
	krbClientField := reflect.Indirect(cr).FieldByName("krbClient")
	krbClientValue := reflect.NewAt(krbClientField.Type(), unsafe.Pointer(krbClientField.UnsafeAddr())).Elem()

	return krbClientValue.Interface().(*client.Client)
}
