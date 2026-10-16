package proxy

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"strings"
	"sync"
	"testing"
	"time"

	_ "github.com/rclone/rclone/backend/local"
	"github.com/rclone/rclone/fs"
	"github.com/rclone/rclone/fs/config/configmap"
	"github.com/rclone/rclone/fs/config/obscure"
	"github.com/rclone/rclone/vfs"
	"github.com/rclone/rclone/vfs/vfscommon"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

func TestRun(t *testing.T) {
	opt := Opt
	cmd := "go run proxy_code.go"
	opt.AuthProxy = cmd
	p := New(context.Background(), &opt, &vfscommon.Opt)

	t.Run("Normal", func(t *testing.T) {
		config, err := p.run(map[string]string{
			"type": "ftp",
			"user": "me",
			"pass": "pass",
			"host": "127.0.0.1",
		})
		require.NoError(t, err)
		assert.Equal(t, configmap.Simple{
			"type":  "ftp",
			"user":  "me-test",
			"pass":  "pass",
			"host":  "127.0.0.1",
			"_root": "",
		}, config)
	})

	t.Run("Error", func(t *testing.T) {
		config, err := p.run(map[string]string{
			"error": "potato",
		})
		assert.Nil(t, config)
		require.Error(t, err)
		require.Contains(t, err.Error(), "potato")
	})

	t.Run("Obscure", func(t *testing.T) {
		config, err := p.run(map[string]string{
			"type":     "ftp",
			"user":     "me",
			"pass":     "pass",
			"host":     "127.0.0.1",
			"_obscure": "pass,user",
		})
		require.NoError(t, err)
		config["user"] = obscure.MustReveal(config["user"])
		config["pass"] = obscure.MustReveal(config["pass"])
		assert.Equal(t, configmap.Simple{
			"type":     "ftp",
			"user":     "me-test",
			"pass":     "pass",
			"host":     "127.0.0.1",
			"_obscure": "pass,user",
			"_root":    "",
		}, config)
	})

	const testUser = "testUser"
	const testPass = "testPass"

	t.Run("call w/Password", func(t *testing.T) {
		// check cache empty
		assert.Equal(t, 0, p.vfsCache.Entries())
		defer p.vfsCache.Clear()

		passwordBytes := []byte(testPass)
		value, err := p.call(testUser, testPass, authPassword)
		require.NoError(t, err)
		entry, ok := value.(cacheEntry)
		require.True(t, ok)

		// check hash is correct in entry
		assert.Equal(t, entry.pwHash, sha256.Sum256(passwordBytes))
		require.NotNil(t, entry.vfs)
		f := entry.vfs.Fs()
		require.NotNil(t, f)
		assert.Equal(t, "proxy-"+testUser, f.Name())
		assert.True(t, strings.HasPrefix(f.String(), "Local file system"))

		// check it is in the cache
		assert.Equal(t, 1, p.vfsCache.Entries())
		cacheValue, ok := p.vfsCache.GetMaybe(testUser)
		assert.True(t, ok)
		assert.Equal(t, value, cacheValue)
	})

	t.Run("Call w/Password", func(t *testing.T) {
		// check cache empty
		assert.Equal(t, 0, p.vfsCache.Entries())
		defer p.vfsCache.Clear()

		vfs, vfsKey, err := p.Call(testUser, testPass, false)
		require.NoError(t, err)
		require.NotNil(t, vfs)
		assert.Equal(t, "proxy-"+testUser, vfs.Fs().Name())
		assert.Equal(t, testUser, vfsKey)

		// check it is in the cache
		assert.Equal(t, 1, p.vfsCache.Entries())
		cacheValue, ok := p.vfsCache.GetMaybe(testUser)
		assert.True(t, ok)
		cacheEntry, ok := cacheValue.(cacheEntry)
		assert.True(t, ok)
		assert.Equal(t, vfs, cacheEntry.vfs)

		// Test Get works while we have something in the cache
		t.Run("Get", func(t *testing.T) {
			assert.Equal(t, vfs, p.Get(testUser))
			assert.Nil(t, p.Get("unknown"))
		})

		// now try again from the cache
		vfs, vfsKey, err = p.Call(testUser, testPass, false)
		require.NoError(t, err)
		require.NotNil(t, vfs)
		assert.Equal(t, "proxy-"+testUser, vfs.Fs().Name())
		assert.Equal(t, testUser, vfsKey)

		// check cache is at the same level
		assert.Equal(t, 1, p.vfsCache.Entries())

		// now try again from the cache but with wrong password
		vfs, vfsKey, err = p.Call(testUser, testPass+"wrong", false)
		require.Error(t, err)
		require.Contains(t, err.Error(), "incorrect password")
		require.Nil(t, vfs)
		require.Equal(t, "", vfsKey)

		// check cache is at the same level
		assert.Equal(t, 1, p.vfsCache.Entries())

	})

	privateKey, privateKeyErr := rsa.GenerateKey(rand.Reader, 2048)
	if privateKeyErr != nil {
		fs.Fatal(nil, "error generating test private key "+privateKeyErr.Error())
	}
	publicKey, publicKeyError := ssh.NewPublicKey(&privateKey.PublicKey)
	if publicKeyError != nil {
		fs.Fatal(nil, "error generating test public key "+publicKeyError.Error())
	}

	publicKeyString := base64.StdEncoding.EncodeToString(publicKey.Marshal())

	t.Run("Call w/PublicKey", func(t *testing.T) {
		// check cache empty
		assert.Equal(t, 0, p.vfsCache.Entries())
		defer p.vfsCache.Clear()

		value, err := p.call(testUser, publicKeyString, authPublicKey)
		require.NoError(t, err)
		entry, ok := value.(cacheEntry)
		require.True(t, ok)

		// check publicKey is correct in entry
		require.NoError(t, err)
		require.NotNil(t, entry.vfs)
		f := entry.vfs.Fs()
		require.NotNil(t, f)
		assert.Equal(t, "proxy-"+testUser, f.Name())
		assert.True(t, strings.HasPrefix(f.String(), "Local file system"))

		// check it is in the cache
		assert.Equal(t, 1, p.vfsCache.Entries())
		cacheValue, ok := p.vfsCache.GetMaybe(testUser)
		assert.True(t, ok)
		assert.Equal(t, value, cacheValue)
	})

	t.Run("call w/PublicKey", func(t *testing.T) {
		// check cache empty
		assert.Equal(t, 0, p.vfsCache.Entries())
		defer p.vfsCache.Clear()

		vfs, vfsKey, err := p.Call(
			testUser,
			publicKeyString,
			true,
		)
		require.NoError(t, err)
		require.NotNil(t, vfs)
		assert.Equal(t, "proxy-"+testUser, vfs.Fs().Name())
		assert.Equal(t, testUser, vfsKey)

		// check it is in the cache
		assert.Equal(t, 1, p.vfsCache.Entries())
		cacheValue, ok := p.vfsCache.GetMaybe(testUser)
		assert.True(t, ok)
		cacheEntry, ok := cacheValue.(cacheEntry)
		assert.True(t, ok)
		assert.Equal(t, vfs, cacheEntry.vfs)

		// Test Get works while we have something in the cache
		t.Run("Get", func(t *testing.T) {
			assert.Equal(t, vfs, p.Get(testUser))
			assert.Nil(t, p.Get("unknown"))
		})

		// now try again from the cache
		vfs, vfsKey, err = p.Call(testUser, publicKeyString, true)
		require.NoError(t, err)
		require.NotNil(t, vfs)
		assert.Equal(t, "proxy-"+testUser, vfs.Fs().Name())
		assert.Equal(t, testUser, vfsKey)

		// check cache is at the same level
		assert.Equal(t, 1, p.vfsCache.Entries())

		// now try again from the cache but with wrong public key
		vfs, vfsKey, err = p.Call(testUser, publicKeyString+"wrong", true)
		require.Error(t, err)
		require.Contains(t, err.Error(), "incorrect public key")
		require.Nil(t, vfs)
		require.Equal(t, "", vfsKey)

		// check cache is at the same level
		assert.Equal(t, 1, p.vfsCache.Entries())
	})
}

// TestCallAccessKeyConcurrentRefresh checks that concurrent refreshes
// which all see a rotated secret end up sharing one backend and one
// cache entry rather than the later ones retiring the entry an
// earlier one created and returned.
func TestCallAccessKeyConcurrentRefresh(t *testing.T) {
	opt := Opt
	opt.AuthProxy = "go run proxy_code.go"
	p := New(context.Background(), &opt, &vfscommon.Opt)
	defer p.Shutdown()

	oldInterval := accessKeyRefreshInterval
	accessKeyRefreshInterval = 0
	defer func() { accessKeyRefreshInterval = oldInterval }()

	VFS, _, err := p.CallAccessKey("CONCURRENT", false)
	require.NoError(t, err)

	// Rotate the secret then refresh from many goroutines at once
	t.Setenv("RCLONE_TEST_PROXY_SECRET_SUFFIX", "-rotated")
	const n = 8
	results := make([]*vfs.VFS, n)
	var wg sync.WaitGroup
	for i := range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			newVFS, secret, err := p.CallAccessKey("CONCURRENT", true)
			assert.NoError(t, err)
			assert.Equal(t, "CONCURRENT-rotated", secret)
			results[i] = newVFS
		}()
	}
	wg.Wait()

	// Every caller must have got the same backend and only one
	// entry was retired
	for i := range n {
		assert.Same(t, VFS, results[i], "goroutine %d got a different backend", i)
	}
	assert.Equal(t, 2, p.vfsCache.Entries())
}

func TestCallAccessKey(t *testing.T) {
	opt := Opt
	opt.AuthProxy = "go run proxy_code.go"
	p := New(context.Background(), &opt, &vfscommon.Opt)
	defer p.Shutdown()

	// Disable refresh rate limiting for this test
	oldInterval := accessKeyRefreshInterval
	accessKeyRefreshInterval = 0
	defer func() { accessKeyRefreshInterval = oldInterval }()

	VFS, secret, err := p.CallAccessKey("AKID", false)
	require.NoError(t, err)
	require.NotNil(t, VFS)
	assert.Equal(t, "AKID-secret", secret)

	// Check the cached entry is returned on the next call
	VFS2, secret2, err := p.CallAccessKey("AKID", false)
	require.NoError(t, err)
	assert.Same(t, VFS, VFS2)
	assert.Equal(t, secret, secret2)

	// Check a different access key ID gets a different backend
	VFS3, secret3, err := p.CallAccessKey("OTHER", false)
	require.NoError(t, err)
	assert.NotSame(t, VFS, VFS3)
	assert.Equal(t, "OTHER-secret", secret3)

	// Check a refresh with an unchanged secret keeps the cached backend
	VFS4, secret4, err := p.CallAccessKey("AKID", true)
	require.NoError(t, err)
	assert.Same(t, VFS, VFS4)
	assert.Equal(t, secret, secret4)

	// Check a refresh with a changed secret returns the new secret.
	// The VFS is the same object as vfs.New shares a live VFS for the
	// same backend and options, which keeps requests in flight under
	// the old secret working.
	t.Setenv("RCLONE_TEST_PROXY_SECRET_SUFFIX", "-rotated")
	entries := p.vfsCache.Entries()
	VFS5, secret5, err := p.CallAccessKey("AKID", true)
	require.NoError(t, err)
	assert.Same(t, VFS, VFS5)
	assert.Equal(t, "AKID-rotated", secret5)
	// The old entry is retired rather than dropped
	assert.Equal(t, entries+1, p.vfsCache.Entries())
	// and can't be reached by naming it as an access key ID with
	// the old secret
	_, retiredFound := p.vfsCache.GetMaybe(retiredAccessKeyCacheKey("AKID", "AKID-secret"))
	assert.True(t, retiredFound)
	assert.NotContains(t, retiredAccessKeyCacheKey("AKID", "AKID-secret"), "AKID-secret")

	// Check a proxy which doesn't return the secret is an error
	_, _, err = p.CallAccessKey("nosecret", false)
	require.ErrorContains(t, err, "_secret_access_key not set")

	// Check a proxy which returns an empty secret is an error
	_, _, err = p.CallAccessKey("emptysecret", false)
	require.ErrorContains(t, err, "_secret_access_key is empty")

	// Check a cached entry without a secret, eg one made by password
	// auth, is never handed out for access key auth
	_, _, err = p.Call("pwuser", "pass", false)
	require.NoError(t, err)
	_, _, err = p.CallAccessKey("pwuser", false)
	require.ErrorContains(t, err, "no secret access key")

	// Check refreshes are rate limited: with a long interval a
	// refresh returns the cached secret without running the proxy
	accessKeyRefreshInterval = time.Hour
	t.Setenv("RCLONE_TEST_PROXY_SECRET_SUFFIX", "-rotated-again")
	VFS6, secret6, err := p.CallAccessKey("AKID", true)
	require.NoError(t, err)
	assert.Same(t, VFS5, VFS6)
	assert.Equal(t, "AKID-rotated", secret6)

	// And with no interval the proxy is run and the rotation seen
	accessKeyRefreshInterval = 0
	_, secret7, err := p.CallAccessKey("AKID", true)
	require.NoError(t, err)
	assert.Equal(t, "AKID-rotated-again", secret7)

	// Check a cached entry is revalidated with the proxy once it is
	// old enough even without a refresh being asked for
	oldRevalidate := accessKeyRevalidateInterval
	defer func() { accessKeyRevalidateInterval = oldRevalidate }()
	t.Setenv("RCLONE_TEST_PROXY_REVOKED", "AKID")
	_, secret8, err := p.CallAccessKey("AKID", false)
	require.NoError(t, err, "cached entry should still be trusted")
	assert.Equal(t, "AKID-rotated-again", secret8)
	accessKeyRevalidateInterval = 0
	_, _, err = p.CallAccessKey("AKID", false)
	require.ErrorContains(t, err, "revoked")
}
