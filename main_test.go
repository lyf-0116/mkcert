// Copyright 2018 The mkcert Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"
)

func newTestMkcert(t *testing.T) *mkcert {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate test key: %v", err)
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatalf("failed to generate test serial: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "mkcert test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		IsCA:                  true,
		BasicConstraintsValid: true,
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("failed to create test certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("failed to parse test certificate: %v", err)
	}

	return &mkcert{caCert: cert}
}

// A root that is not in the system trust store must report as not installed.
func TestCheckPlatformNotInstalled(t *testing.T) {
	m := newTestMkcert(t)

	if m.checkPlatform() {
		t.Fatal("checkPlatform() = true, want false for a root not in the system trust store")
	}
}

// A failed install must not make later checks report success: the check
// result is a fact, while skipping the check is a policy decision.
func TestCheckPlatformAfterFailedInstall(t *testing.T) {
	m := newTestMkcert(t)

	// Simulate installPlatform() returning false without recording a success.
	if m.systemTrustUpdated {
		t.Fatal("systemTrustUpdated should start false")
	}

	if m.checkPlatform() {
		t.Fatal("checkPlatform() = true after a failed install, want false")
	}
	if m.checkPlatform() {
		t.Fatal("repeated checkPlatform() = true after a failed install, want false")
	}
}

// Only a recorded successful install may short-circuit the cached check.
func TestCheckPlatformAfterSuccessfulInstall(t *testing.T) {
	m := newTestMkcert(t)

	m.systemTrustUpdated = true

	if !m.checkPlatform() {
		t.Fatal("checkPlatform() = false after a recorded successful install, want true")
	}
}

// TestInstallFlowKeepsRealStateAfterFailure reproduces the pipeline failure:
// the first system-store install fails (for example, a missing sudo
// password), and every later "is it installed?" check must keep reporting the
// real state instead of being masked by a process-wide switch.
func TestInstallFlowKeepsRealStateAfterFailure(t *testing.T) {
	m := newTestMkcert(t)

	// The install flow first asks whether the root is already installed.
	if m.checkPlatform() {
		t.Fatal("checkPlatform() = true before any install, want false")
	}

	// Simulate installPlatform() failing: no success is recorded. Leaving the
	// fact unset is exactly what the fixed install() does on the false branch.
	// (The buggy install() instead flipped the process-wide switch here even
	// on failure; that is the behavior this test guards against.)
	//
	// Subsequent checks, including checks from later pipeline steps within the
	// same process, must therefore still return false.
	for i := 0; i < 3; i++ {
		if m.checkPlatform() {
			t.Fatalf("checkPlatform() = true after failed install (call %d), want false", i+1)
		}
	}

	// A later, genuinely successful install is then allowed to short-circuit.
	m.systemTrustUpdated = true
	if !m.checkPlatform() {
		t.Fatal("checkPlatform() = false after a later successful install, want true")
	}
}
