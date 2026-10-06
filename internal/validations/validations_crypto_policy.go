package validations

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/openshift/check-payload/internal/types"
)

// CryptoPolicyStatePath is where update-crypto-policies records the active policy.
const CryptoPolicyStatePath = "/etc/crypto-policies/state/current"

// rhel9ReleasePrefix limits the check to RHEL 9 images. RHEL 9 needs the :PQ
// subpolicy to enable post-quantum algorithms in OpenSSL, while the RHEL 10
// DEFAULT policy already includes them, so both report different values for
// the same outcome.
const rhel9ReleasePrefix = "Red Hat Enterprise Linux release 9."

// ValidateCryptoPolicy checks that a RHEL 9 image's active crypto policy is
// one of required_crypto_policies. Images that are not RHEL 9, or that do not
// ship crypto-policies at all, are skipped.
func ValidateCryptoPolicy(cfg *types.Config, mountPath string) *types.ValidationError {
	releasePath, err := GetTargetPath(mountPath)
	if err != nil {
		return nil
	}
	release, err := os.ReadFile(releasePath)
	if err != nil || !bytes.HasPrefix(release, []byte(rhel9ReleasePrefix)) {
		return nil
	}

	state, err := os.ReadFile(filepath.Join(mountPath, CryptoPolicyStatePath))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return types.NewValidationError(err)
	}

	policy := strings.TrimSpace(string(state))
	if slices.Contains(cfg.GetRequiredCryptoPolicies(), policy) {
		return nil
	}
	return types.NewValidationError(fmt.Errorf("%w: got %q, want one of %q", types.ErrCryptoPolicyNotAllowed, policy, cfg.GetRequiredCryptoPolicies()))
}
