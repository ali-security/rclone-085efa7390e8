// Serve s3 tests set up a server and run the integration tests
// for the s3 remote against it.

package s3

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
	"github.com/rclone/gofakes3/signature"
	_ "github.com/rclone/rclone/backend/local"
	"github.com/rclone/rclone/cmd/serve/proxy"
	"github.com/rclone/rclone/cmd/serve/servetest"
	"github.com/rclone/rclone/fs"
	"github.com/rclone/rclone/fs/config/configmap"
	"github.com/rclone/rclone/fs/hash"
	"github.com/rclone/rclone/fs/object"
	"github.com/rclone/rclone/fs/rc"
	"github.com/rclone/rclone/fstest"
	"github.com/rclone/rclone/lib/random"
	"github.com/rclone/rclone/vfs/vfscommon"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	endpoint = "localhost:0"
)

// Configure and serve the server
//
// If f is nil the server is expected to be using an auth proxy, in
// which case the credentials are handed to the test proxy via the
// environment rather than --auth-key.
func serveS3(t *testing.T, f fs.Fs) (testURL string, keyid string, keysec string, w *Server) {
	keyid = random.String(16)
	keysec = random.String(16)
	opt := Opt // copy default options
	if f == nil {
		t.Setenv("RCLONE_TEST_PROXY_AUTH_KEY", fmt.Sprintf("%s,%s", keyid, keysec))
	} else {
		opt.AuthKey = []string{fmt.Sprintf("%s,%s", keyid, keysec)}
	}
	opt.HTTP.ListenAddr = []string{endpoint}
	w, _ = newServer(context.Background(), f, &opt, &vfscommon.Opt, &proxy.Opt)
	go func() {
		require.NoError(t, w.Serve())
	}()
	testURL = w.server.URLs()[0]

	return
}

// TestS3 runs the s3 server then runs the unit tests for the
// s3 remote against it.
func TestS3(t *testing.T) {
	start := func(f fs.Fs) (configmap.Simple, func()) {
		testURL, keyid, keysec, _ := serveS3(t, f)
		// Config for the backend we'll use to connect to the server
		config := configmap.Simple{
			"type":              "s3",
			"provider":          "Rclone",
			"endpoint":          testURL,
			"access_key_id":     keyid,
			"secret_access_key": keysec,
		}

		return config, func() {}
	}

	servetest.Run(t, "s3", start)
}

// tests using the minio client
func TestEncodingWithMinioClient(t *testing.T) {
	cases := []struct {
		description string
		bucket      string
		path        string
		filename    string
		expected    string
	}{
		{
			description: "weird file in bucket root",
			bucket:      "mybucket",
			path:        "",
			filename:    " file with w€r^d ch@r \\#~+§4%&'. txt ",
		},
		{
			description: "weird file inside a weird folder",
			bucket:      "mybucket",
			path:        "ä#/नेपाल&/?/",
			filename:    " file with w€r^d ch@r \\#~+§4%&'. txt ",
		},
	}

	for _, tt := range cases {
		t.Run(tt.description, func(t *testing.T) {
			fstest.Initialise()
			f, _, clean, err := fstest.RandomRemote()
			assert.NoError(t, err)
			defer clean()
			err = f.Mkdir(context.Background(), path.Join(tt.bucket, tt.path))
			assert.NoError(t, err)

			buf := bytes.NewBufferString("contents")
			uploadHash := hash.NewMultiHasher()
			in := io.TeeReader(buf, uploadHash)

			obji := object.NewStaticObjectInfo(
				path.Join(tt.bucket, tt.path, tt.filename),
				time.Now(),
				int64(buf.Len()),
				true,
				nil,
				nil,
			)
			_, err = f.Put(context.Background(), in, obji)
			assert.NoError(t, err)

			endpoint, keyid, keysec, _ := serveS3(t, f)
			testURL, _ := url.Parse(endpoint)
			minioClient, err := minio.New(testURL.Host, &minio.Options{
				Creds:  credentials.NewStaticV4(keyid, keysec, ""),
				Secure: false,
			})
			assert.NoError(t, err)

			buckets, err := minioClient.ListBuckets(context.Background())
			assert.NoError(t, err)
			assert.Equal(t, buckets[0].Name, tt.bucket)
			objects := minioClient.ListObjects(context.Background(), tt.bucket, minio.ListObjectsOptions{
				Recursive: true,
			})
			for object := range objects {
				assert.Equal(t, path.Join(tt.path, tt.filename), object.Key)
			}
		})
	}
}

type FileStuct struct {
	path     string
	filename string
}

type TestCase struct {
	description string
	bucket      string
	files       []FileStuct
	keyID       string
	keySec      string
	shouldFail  bool
}

func testListBuckets(t *testing.T, cases []TestCase, useProxy bool) {
	fstest.Initialise()

	var f fs.Fs
	if useProxy {
		// the backend config will be made by the proxy
		prog, err := filepath.Abs("../servetest/proxy_code.go")
		require.NoError(t, err)
		files, err := filepath.Abs("testdata")
		require.NoError(t, err)
		cmd := "go run " + prog + " " + files

		// FIXME: this is untidy setting a global variable!
		proxy.Opt.AuthProxy = cmd
		defer func() {
			proxy.Opt.AuthProxy = ""
		}()

		f = nil
	} else {
		// create a test Fs
		var err error
		f, err = fs.NewFs(context.Background(), "testdata")
		require.NoError(t, err)
	}

	for _, tt := range cases {
		t.Run(tt.description, func(t *testing.T) {
			endpoint, keyid, keysec, s := serveS3(t, f)
			defer func() {
				assert.NoError(t, s.server.Shutdown())
			}()

			if tt.keyID != "" {
				keyid = tt.keyID
			}
			if tt.keySec != "" {
				keysec = tt.keySec
			}

			testURL, _ := url.Parse(endpoint)
			minioClient, err := minio.New(testURL.Host, &minio.Options{
				Creds:  credentials.NewStaticV4(keyid, keysec, ""),
				Secure: false,
			})
			assert.NoError(t, err)

			buckets, err := minioClient.ListBuckets(context.Background())
			if tt.shouldFail {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				require.NotEmpty(t, buckets)
				assert.Equal(t, buckets[0].Name, tt.bucket)

				o := minioClient.ListObjects(context.Background(), tt.bucket, minio.ListObjectsOptions{
					Recursive: true,
				})
				// save files after reading from channel
				objects := []string{}
				for object := range o {
					objects = append(objects, object.Key)
				}

				for _, tt := range tt.files {
					file := path.Join(tt.path, tt.filename)
					found := slices.Contains(objects, file)
					require.Equal(t, true, found, "Object not found: "+file)
				}
			}
		})
	}
}

func TestListBuckets(t *testing.T) {
	var cases = []TestCase{
		{
			description: "list buckets",
			bucket:      "mybucket",
			files: []FileStuct{
				{
					path:     "",
					filename: "lorem.txt",
				},
				{
					path:     "foo",
					filename: "bar.txt",
				},
			},
		},
		{
			description: "list buckets: wrong s3 key",
			bucket:      "mybucket",
			keyID:       "invalid",
			shouldFail:  true,
		},
		{
			description: "list buckets: wrong s3 secret",
			bucket:      "mybucket",
			keySec:      "invalid",
			shouldFail:  true,
		},
	}

	testListBuckets(t, cases, false)
}

func TestListBucketsAuthProxy(t *testing.T) {
	var cases = []TestCase{
		{
			description: "list buckets",
			bucket:      "mybucket",
			files: []FileStuct{
				{
					path:     "",
					filename: "lorem.txt",
				},
				{
					path:     "foo",
					filename: "bar.txt",
				},
			},
		},
		{
			description: "list buckets: unknown s3 key",
			bucket:      "mybucket",
			keyID:       random.String(16),
			shouldFail:  true,
		},
		{
			description: "list buckets: wrong s3 secret",
			bucket:      "mybucket",
			keySec:      "invalid",
			shouldFail:  true,
		},
	}

	testListBuckets(t, cases, true)
}

// TestNewServerPerServerAuthProxy checks that a per-server proxyOpt.AuthProxy
// enables proxy mode even when the process-global proxy.Opt.AuthProxy is empty,
// which is the normal case when the server is configured via serve/start.
//
// If it didn't, the remote would be served with a fixed VFS and no
// authentication.
func TestNewServerPerServerAuthProxy(t *testing.T) {
	// Ensure the global is empty so we only test the per-server option.
	assert.Equal(t, "", proxy.Opt.AuthProxy)

	fstest.Initialise()
	ctx := context.Background()
	f, err := fs.NewFs(ctx, "testdata")
	require.NoError(t, err)

	opt := Opt
	opt.HTTP.ListenAddr = []string{endpoint}

	proxyOpt := proxy.Opt
	proxyOpt.AuthProxy = "/path/to/auth/proxy"

	w, err := newServer(ctx, f, &opt, &vfscommon.Opt, &proxyOpt)
	require.NoError(t, err)
	defer func() {
		assert.NoError(t, w.Shutdown())
	}()
	assert.True(t, w.provider.IsProxy(), "expected auth proxy to be enabled by per-server option")
	assert.Nil(t, w.provider.VFS(), "expected no fixed VFS when auth proxy is in use")

	// A request which wasn't authorized by the proxy must not get a VFS
	VFS, err := w.getVFS(ctx)
	assert.Error(t, err)
	assert.Nil(t, VFS)
	_, err = newBackend(w).ListBuckets(ctx)
	assert.Error(t, err, "expected anonymous bucket listing to be refused")
}

// TestAuthProxyEmptySecret checks that a request for an arbitrary
// access key ID signed with an empty secret is refused when using an
// auth proxy without --auth-key.
func TestAuthProxyEmptySecret(t *testing.T) {
	fstest.Initialise()

	prog, err := filepath.Abs("../servetest/proxy_code.go")
	require.NoError(t, err)
	files, err := filepath.Abs("testdata")
	require.NoError(t, err)
	proxy.Opt.AuthProxy = "go run " + prog + " " + files
	defer func() {
		proxy.Opt.AuthProxy = ""
	}()

	endpoint, keyid, _, s := serveS3(t, nil)
	defer func() {
		assert.NoError(t, s.server.Shutdown())
	}()

	for _, accessKeyID := range []string{keyid, random.String(16)} {
		req, err := http.NewRequest("GET", endpoint+"/", nil)
		require.NoError(t, err)
		req.Header.Set("X-Amz-Content-Sha256", "UNSIGNED-PAYLOAD")
		signer := v4.NewSigner()
		err = signer.SignHTTP(context.Background(), aws.Credentials{AccessKeyID: accessKeyID, SecretAccessKey: ""}, req, "UNSIGNED-PAYLOAD", "s3", "us-east-1", time.Now())
		require.NoError(t, err)

		resp, err := http.DefaultClient.Do(req)
		require.NoError(t, err)
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		assert.Equal(t, http.StatusForbidden, resp.StatusCode, string(body))
		assert.NotContains(t, string(body), "ListAllMyBucketsResult")
	}
}

// TestAuthProxyKeysNotRegistered checks that secrets supplied by the
// auth proxy are never registered in gofakes3's process wide key
// store where any other serve s3 instance in the process would honour
// them.
func TestAuthProxyKeysNotRegistered(t *testing.T) {
	fstest.Initialise()

	prog, err := filepath.Abs("../servetest/proxy_code.go")
	require.NoError(t, err)
	files, err := filepath.Abs("testdata")
	require.NoError(t, err)
	proxy.Opt.AuthProxy = "go run " + prog + " " + files
	defer func() {
		proxy.Opt.AuthProxy = ""
	}()

	endpoint, keyid, keysec, s := serveS3(t, nil)
	defer func() {
		assert.NoError(t, s.server.Shutdown())
	}()

	sign := func() *http.Request {
		req, err := http.NewRequest("GET", endpoint+"/", nil)
		require.NoError(t, err)
		req.Header.Set("X-Amz-Content-Sha256", "UNSIGNED-PAYLOAD")
		signer := v4.NewSigner()
		err = signer.SignHTTP(context.Background(), aws.Credentials{AccessKeyID: keyid, SecretAccessKey: keysec}, req, "UNSIGNED-PAYLOAD", "s3", "us-east-1", time.Now())
		require.NoError(t, err)
		return req
	}

	// A correctly signed request is accepted by the server
	resp, err := http.DefaultClient.Do(sign())
	require.NoError(t, err)
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode, string(body))

	// But the key it used must not be in the global key store
	assert.NotEqual(t, signature.ErrNone, signature.V4SignVerify(sign()), "proxy secret was registered in the gofakes3 key store")
}

// serveS3AuthProxyWithAuthKey starts a server using the test auth proxy
// which knows only proxyKeyID with proxySecret, while also being given
// a different --auth-key pair.
func serveS3AuthProxyWithAuthKey(t *testing.T, proxyKeyID, proxySecret, authKeyID, authSecret string) (testURL string, w *Server) {
	fstest.Initialise()
	prog, err := filepath.Abs("../servetest/proxy_code.go")
	require.NoError(t, err)
	files, err := filepath.Abs("testdata")
	require.NoError(t, err)
	proxyOpt := proxy.Opt
	proxyOpt.AuthProxy = "go run " + prog + " " + files
	t.Setenv("RCLONE_TEST_PROXY_AUTH_KEY", proxyKeyID+","+proxySecret)

	opt := Opt
	opt.AuthKey = []string{authKeyID + "," + authSecret}
	opt.HTTP.ListenAddr = []string{endpoint}
	w, err = newServer(context.Background(), nil, &opt, &vfscommon.Opt, &proxyOpt)
	require.NoError(t, err)
	go func() {
		assert.NoError(t, w.Serve())
	}()
	return w.server.URLs()[0], w
}

// doSigned makes a signed list buckets request returning the status code
func doSigned(t *testing.T, testURL, accessKeyID, secret string) int {
	req, err := http.NewRequest("GET", testURL, nil)
	require.NoError(t, err)
	req.Header.Set("X-Amz-Content-Sha256", "UNSIGNED-PAYLOAD")
	err = v4.NewSigner().SignHTTP(context.Background(), aws.Credentials{AccessKeyID: accessKeyID, SecretAccessKey: secret}, req, "UNSIGNED-PAYLOAD", "s3", "us-east-1", time.Now())
	require.NoError(t, err)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	return resp.StatusCode
}

// TestAuthProxyIgnoresAuthKey checks that when --auth-proxy and
// --auth-key are both set the --auth-key secret can't be used with
// any access key ID, and the request is only accepted when signed
// with the secret the proxy returned for the access key ID.
func TestAuthProxyIgnoresAuthKey(t *testing.T) {
	proxyKeyID, proxySecret := random.String(16), random.String(16)
	authKeyID, authSecret := random.String(16), random.String(16)
	testURL, s := serveS3AuthProxyWithAuthKey(t, proxyKeyID, proxySecret, authKeyID, authSecret)
	defer func() {
		assert.NoError(t, s.server.Shutdown())
	}()

	assert.Equal(t, http.StatusOK, doSigned(t, testURL, proxyKeyID, proxySecret))
	otherKeyID := random.String(16)
	assert.Equal(t, http.StatusForbidden, doSigned(t, testURL, otherKeyID, authSecret), "--auth-key secret accepted for an unknown access key ID")
	assert.Equal(t, http.StatusForbidden, doSigned(t, testURL, authKeyID, authSecret), "--auth-key pair accepted though the proxy doesn't know it")
	assert.Equal(t, http.StatusForbidden, doSigned(t, testURL, proxyKeyID, authSecret), "--auth-key secret accepted for the proxy's access key ID")
	assert.Equal(t, http.StatusForbidden, doSigned(t, testURL, proxyKeyID, ""), "empty secret accepted")

	// None of these may have been put in the global key store
	for _, accessKeyID := range []string{otherKeyID, authKeyID, proxyKeyID} {
		req, err := http.NewRequest("GET", testURL, nil)
		require.NoError(t, err)
		req.Header.Set("X-Amz-Content-Sha256", "UNSIGNED-PAYLOAD")
		require.NoError(t, v4.NewSigner().SignHTTP(context.Background(), aws.Credentials{AccessKeyID: accessKeyID, SecretAccessKey: authSecret}, req, "UNSIGNED-PAYLOAD", "s3", "us-east-1", time.Now()))
		assert.NotEqual(t, signature.ErrNone, signature.V4SignVerify(req), "key %q registered in the gofakes3 key store", accessKeyID)
	}
}

// TestAuthProxyPresigned checks presigned URLs are authenticated
// against the secret supplied by the auth proxy.
func TestAuthProxyPresigned(t *testing.T) {
	proxyKeyID, proxySecret := random.String(16), random.String(16)
	authKeyID, authSecret := random.String(16), random.String(16)
	testURL, s := serveS3AuthProxyWithAuthKey(t, proxyKeyID, proxySecret, authKeyID, authSecret)
	defer func() {
		assert.NoError(t, s.server.Shutdown())
	}()

	get := func(accessKeyID, secret string) int {
		req, err := http.NewRequest("GET", testURL, nil)
		require.NoError(t, err)
		presignedURL, _, err := v4.NewSigner().PresignHTTP(context.Background(), aws.Credentials{AccessKeyID: accessKeyID, SecretAccessKey: secret}, req, "UNSIGNED-PAYLOAD", "s3", "us-east-1", time.Now())
		require.NoError(t, err)
		resp, err := http.Get(presignedURL)
		require.NoError(t, err)
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		return resp.StatusCode
	}

	assert.Equal(t, http.StatusOK, get(proxyKeyID, proxySecret))
	assert.Equal(t, http.StatusForbidden, get(proxyKeyID, ""), "presigned URL with empty secret accepted")
	assert.Equal(t, http.StatusForbidden, get(random.String(16), ""), "presigned URL for unknown access key ID accepted")
	assert.Equal(t, http.StatusForbidden, get(random.String(16), authSecret), "presigned URL with --auth-key secret accepted")
}

// TestV4SignVerifyWithSecret checks v4SignVerifyWithSecret gives the
// same answers as gofakes3's own V4SignVerify does for keys registered
// with it.
func TestV4SignVerifyWithSecret(t *testing.T) {
	ctx := context.Background()
	accessKeyID := random.String(16)
	secret := random.String(16)
	// Register the key so gofakes3's verifier can be compared
	signature.StoreKeys(map[string]string{accessKeyID: secret})

	// A new signer is needed for each request as a signer caches the
	// signing key it derives by access key ID, not by secret.
	newSigner := func() *v4.Signer {
		return v4.NewSigner(func(o *v4.SignerOptions) {
			o.DisableURIPathEscaping = true
		})
	}
	newRequest := func(method, rawURL, payloadHash string) *http.Request {
		req, err := http.NewRequest(method, rawURL, nil)
		require.NoError(t, err)
		req.Header.Set("X-Amz-Content-Sha256", payloadHash)
		return req
	}
	sign := func(req *http.Request, payloadHash, secret string, when time.Time) *http.Request {
		err := newSigner().SignHTTP(ctx, aws.Credentials{AccessKeyID: accessKeyID, SecretAccessKey: secret}, req, payloadHash, "s3", "us-east-1", when)
		require.NoError(t, err)
		return req
	}
	presign := func(method, rawURL, secret string) *http.Request {
		req, err := http.NewRequest(method, rawURL, nil)
		require.NoError(t, err)
		presignedURL, _, err := newSigner().PresignHTTP(ctx, aws.Credentials{AccessKeyID: accessKeyID, SecretAccessKey: secret}, req, "UNSIGNED-PAYLOAD", "s3", "us-east-1", time.Now())
		require.NoError(t, err)
		presigned, err := http.NewRequest(method, presignedURL, nil)
		require.NoError(t, err)
		return presigned
	}
	// The server sees the host in r.Host rather than the header
	serverSide := func(req *http.Request) *http.Request {
		req.Host = req.URL.Host
		return req
	}

	const bodyHash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	const testURL = "http://127.0.0.1:8080/bucket/dir/file%20with%20spaces%20%E2%82%AC.txt?list-type=2&prefix=a%20b"
	for _, test := range []struct {
		name string
		req  *http.Request
		want error
	}{
		{"unsigned payload", sign(newRequest("GET", testURL, "UNSIGNED-PAYLOAD"), "UNSIGNED-PAYLOAD", secret, time.Now()), nil},
		{"signed payload", sign(newRequest("PUT", testURL, bodyHash), bodyHash, secret, time.Now()), nil},
		{"root", sign(newRequest("GET", "http://127.0.0.1:8080/", "UNSIGNED-PAYLOAD"), "UNSIGNED-PAYLOAD", secret, time.Now()), nil},
		{"presigned", presign("GET", testURL, secret), nil},
		{"wrong secret", sign(newRequest("GET", testURL, "UNSIGNED-PAYLOAD"), "UNSIGNED-PAYLOAD", "wrong", time.Now()), errSignatureDoesNotMatch},
		{"empty secret", sign(newRequest("GET", testURL, "UNSIGNED-PAYLOAD"), "UNSIGNED-PAYLOAD", "", time.Now()), errSignatureDoesNotMatch},
		{"presigned wrong secret", presign("GET", testURL, "wrong"), errSignatureDoesNotMatch},
		{"presigned empty secret", presign("GET", testURL, ""), errSignatureDoesNotMatch},
		{"expired", sign(newRequest("GET", testURL, "UNSIGNED-PAYLOAD"), "UNSIGNED-PAYLOAD", secret, time.Now().Add(-time.Hour)), errSigExpiredRequest},
	} {
		t.Run(test.name, func(t *testing.T) {
			req := serverSide(test.req)
			err := v4SignVerifyWithSecret(req, secret)
			if test.want == nil {
				require.NoError(t, err)
				assert.Equal(t, signature.ErrNone, signature.V4SignVerify(req), "gofakes3 disagrees")
			} else {
				require.ErrorIs(t, err, test.want)
				assert.NotEqual(t, signature.ErrNone, signature.V4SignVerify(req), "gofakes3 disagrees")
			}
		})
	}

	// A request with no signature is refused
	err := v4SignVerifyWithSecret(serverSide(newRequest("GET", testURL, "UNSIGNED-PAYLOAD")), secret)
	require.Error(t, err)
	assert.NotErrorIs(t, err, errSignatureDoesNotMatch)
}

func TestRc(t *testing.T) {
	servetest.TestRc(t, rc.Params{
		"type":           "s3",
		"vfs_cache_mode": "off",
	})
}
