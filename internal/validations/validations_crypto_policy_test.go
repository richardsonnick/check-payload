package validations

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/openshift/check-payload/internal/types"
)

func TestValidateCryptoPolicy(t *testing.T) {
	const (
		rhel9  = "Red Hat Enterprise Linux release 9.8 (Plow)"
		rhel10 = "Red Hat Enterprise Linux release 10.1 (Coughlan)"
	)

	writeFile := func(t *testing.T, root, path, content string) {
		t.Helper()
		full := filepath.Join(root, path)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	tests := []struct {
		name     string
		release  string
		policy   string
		required []string
		wantErr  bool
	}{
		{
			name:     "RHEL 9 with DEFAULT:PQ passes",
			release:  rhel9,
			policy:   "DEFAULT:PQ\n",
			required: []string{"DEFAULT:PQ"},
		},
		{
			name:     "RHEL 9 with DEFAULT fails",
			release:  rhel9,
			policy:   "DEFAULT\n",
			required: []string{"DEFAULT:PQ"},
			wantErr:  true,
		},
		{
			name:     "RHEL 9 with another allowed policy passes",
			release:  rhel9,
			policy:   "FIPS:PQ\n",
			required: []string{"DEFAULT:PQ", "FIPS:PQ"},
		},
		{
			name:     "RHEL 9 without crypto-policies is skipped",
			release:  rhel9,
			required: []string{"DEFAULT:PQ"},
		},
		{
			name:     "RHEL 10 is skipped",
			release:  rhel10,
			policy:   "DEFAULT\n",
			required: []string{"DEFAULT:PQ"},
		},
		{
			name:     "image without release file is skipped",
			policy:   "DEFAULT\n",
			required: []string{"DEFAULT:PQ"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			if tc.release != "" {
				writeFile(t, root, releaseFilePath, tc.release)
			}
			if tc.policy != "" {
				writeFile(t, root, CryptoPolicyStatePath, tc.policy)
			}
			cfg := &types.Config{ConfigFile: types.ConfigFile{RequiredCryptoPolicies: tc.required}}

			ve := ValidateCryptoPolicy(cfg, root)

			if !tc.wantErr {
				if ve != nil {
					t.Fatalf("expected no error, got %v", ve.GetError())
				}
				return
			}
			if ve == nil {
				t.Fatal("expected error, got nil")
			}
			if !errors.Is(ve.GetError(), types.ErrCryptoPolicyNotAllowed) {
				t.Errorf("expected ErrCryptoPolicyNotAllowed, got %v", ve.GetError())
			}
			if ve.Level != types.Error {
				t.Errorf("expected error level, got %v", ve.Level)
			}
		})
	}
}
