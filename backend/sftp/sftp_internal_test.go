//go:build !plan9

package sftp

import (
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestShellEscapeUnix(t *testing.T) {
	for i, test := range []struct {
		unescaped, escaped string
	}{
		{"", ""},
		{"/this/is/harmless", "/this/is/harmless"},
		{"$(rm -rf /)", "\\$\\(rm\\ -rf\\ /\\)"},
		{"/test/\n", "/test/'\n'"},
		{":\"'", ":\\\"\\'"},
	} {
		got, err := quoteOrEscapeShellPath("unix", test.unescaped)
		assert.NoError(t, err)
		assert.Equal(t, test.escaped, got, fmt.Sprintf("Test %d unescaped = %q", i, test.unescaped))
	}
}

func TestShellEscapeCmd(t *testing.T) {
	for i, test := range []struct {
		unescaped, escaped string
		ok                 bool
	}{
		{"", "\"\"", true},
		{"c:/this/is/harmless", "\"c:/this/is/harmless\"", true},
		{"c:/test&notepad", "\"c:/test&notepad\"", true},
		{"c:/test\"&\"notepad", "", false},
	} {
		got, err := quoteOrEscapeShellPath("cmd", test.unescaped)
		if test.ok {
			assert.NoError(t, err)
			assert.Equal(t, test.escaped, got, fmt.Sprintf("Test %d unescaped = %q", i, test.unescaped))
		} else {
			assert.Error(t, err)
		}
	}
}

func TestShellEscapePowerShell(t *testing.T) {
	// PowerShell treats U+2018, U+2019, U+201A and U+201B as single-quote
	// delimiters in addition to the ASCII apostrophe, so all of them are
	// doubled inside the wrapping apostrophes. Doubling is PowerShell's escape
	// for a literal delimiter and preserves the exact character.
	unquote := strings.NewReplacer("''", "'", "‘‘", "‘", "’’", "’", "‚‚", "‚", "‛‛", "‛")
	for i, test := range []struct {
		unescaped, escaped string
	}{
		{"", "''"},
		{"c:/this/is/harmless", "'c:/this/is/harmless'"},
		{"c:/test&notepad", "'c:/test&notepad'"},
		{"c:/test\"&\"notepad", "'c:/test\"&\"notepad'"},
		{"c:/test'&'notepad", "'c:/test''&''notepad'"},
		// injection attempts via the ASCII apostrophe and each smart quote
		{"x';calc;#", "'x'';calc;#'"},
		{"x’;calc;#", "'x’’;calc;#'"},
		{"x‘;calc;#", "'x‘‘;calc;#'"},
		{"x‚;calc;#", "'x‚‚;calc;#'"},
		{"x‛;calc;#", "'x‛‛;calc;#'"},
	} {
		got, err := quoteOrEscapeShellPath("powershell", test.unescaped)
		assert.NoError(t, err)
		assert.Equal(t, test.escaped, got, fmt.Sprintf("Test %d unescaped = %q", i, test.unescaped))
		// Every single-quote delimiter must appear an even number of times so
		// none is left unpaired to close the literal early.
		for _, q := range []string{"'", "‘", "’", "‚", "‛"} {
			assert.Zero(t, strings.Count(got, q)%2, fmt.Sprintf("Test %d odd %q count in %q", i, q, got))
		}
		// Undoubling the quoted body recovers the original path exactly.
		assert.Equal(t, test.unescaped, unquote.Replace(got[1:len(got)-1]), fmt.Sprintf("Test %d round-trip", i))
	}
}

func TestParseHash(t *testing.T) {
	for i, test := range []struct {
		sshOutput, checksum string
	}{
		{"8dbc7733dbd10d2efc5c0a0d8dad90f958581821  RELEASE.md\n", "8dbc7733dbd10d2efc5c0a0d8dad90f958581821"},
		{"03cfd743661f07975fa2f1220c5194cbaff48451  -\n", "03cfd743661f07975fa2f1220c5194cbaff48451"},
	} {
		got := parseHash([]byte(test.sshOutput))
		assert.Equal(t, test.checksum, got, fmt.Sprintf("Test %d sshOutput = %q", i, test.sshOutput))
	}
}

func TestParseUsage(t *testing.T) {
	for i, test := range []struct {
		sshOutput string
		usage     [3]int64
	}{
		{"Filesystem     1K-blocks     Used Available Use% Mounted on\n/dev/root       91283092 81111888  10154820  89% /", [3]int64{93473886208, 83058573312, 10398535680}},
		{"Filesystem     1K-blocks  Used Available Use% Mounted on\ntmpfs             818256  1636    816620   1% /run", [3]int64{837894144, 1675264, 836218880}},
		{"Filesystem   1024-blocks     Used Available Capacity iused      ifree %iused  Mounted on\n/dev/disk0s2   244277768 94454848 149566920    39%  997820 4293969459    0%   /", [3]int64{250140434432, 96721764352, 153156526080}},
	} {
		gotSpaceTotal, gotSpaceUsed, gotSpaceAvail := parseUsage([]byte(test.sshOutput))
		assert.Equal(t, test.usage, [3]int64{gotSpaceTotal, gotSpaceUsed, gotSpaceAvail}, fmt.Sprintf("Test %d sshOutput = %q", i, test.sshOutput))
	}
}
