package echo_test

import (
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/vuln-list-update/echo"
	"github.com/aquasecurity/vuln-list-update/osv"
)

func TestOSVUpdater_Update(t *testing.T) {
	tests := []struct {
		name      string
		path      string
		wantFiles []string
		wantErr   string
	}{
		{
			name: "happy path",
			wantFiles: []string{
				filepath.Join("echo-osv", "pip", "ECHO-7db2-03aa-5591.json"),
				// The OS entry ("Echo"/pytorch) is listed before the app entry
				// ("Echo:PyPI"/torch). It must be dropped, and the file written
				// under the remaining app package's directory.
				filepath.Join("echo-osv", "torch", "ECHO-9320-f34e-79db.json"),
				// Maven coordinates (groupId:artifactId) route to a nested
				// groupId/artifactId path (colon -> slash).
				filepath.Join("echo-osv", "com.fasterxml.jackson.core", "jackson-databind", "ECHO-5950-3ca7-8a02.json"),
				// Scoped npm names (@scope/name) nest under the scope
				// directory via their literal slash.
				filepath.Join("echo-osv", "@tootallnate", "once", "ECHO-318f-4145-6b35.json"),
			},
		},
		{
			name:    "sad path, unable to download archive",
			path:    "/unknown.zip",
			wantErr: "bad response code: 404",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/osv/all.zip" {
					http.NotFound(w, r)
					return
				}
				http.ServeFile(w, r, filepath.Join("testdata", "osv-all.zip"))
			}))
			defer ts.Close()

			testDir := t.TempDir()
			testURL := ts.URL + "/osv/all.zip"
			if tt.path != "" {
				testURL = ts.URL + tt.path
			}

			ecosystems := map[string]osv.Ecosystem{
				"echo": {
					Dir:     "echo-osv",
					URL:     testURL,
					Exclude: echo.IsOSPackage,
				},
			}

			db := echo.NewOSVUpdater(echo.WithOSVDir(testDir), echo.WithOSVEcosystems(ecosystems))

			err := db.Update()
			if tt.wantErr != "" {
				require.ErrorContains(t, err, tt.wantErr)
				return
			}
			require.NoError(t, err)

			for _, wantFile := range tt.wantFiles {
				got, err := os.ReadFile(filepath.Join(testDir, wantFile))
				require.NoError(t, err)

				want, err := os.ReadFile(filepath.Join("testdata", "osv-golden", wantFile))
				require.NoError(t, err)

				assert.JSONEq(t, string(want), string(got))
			}

			err = filepath.WalkDir(testDir, func(path string, d fs.DirEntry, err error) error {
				require.NoError(t, err)
				if !d.Type().IsRegular() {
					return nil
				}

				got, err := os.ReadFile(path)
				require.NoError(t, err, path)

				rel, err := filepath.Rel(testDir, path)
				require.NoError(t, err, path)

				goldenPath := filepath.Join("testdata", "osv-golden", rel)
				want, err := os.ReadFile(goldenPath)
				require.NoError(t, err, goldenPath)

				assert.JSONEq(t, string(want), string(got), path)

				return nil
			})
			require.NoError(t, err)
		})
	}
}
