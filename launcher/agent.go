package main

import (
	"bytes"
	"context"
	"crypto"
	"fmt"
	"io"
	"net/http"

	"github.com/google/go-tpm-tools/cel"
	"github.com/google/go-tpm-tools/client"
	"github.com/google/go-tpm-tools/launcher/internal/verifier"
	pb "github.com/google/go-tpm-tools/proto/attest"
)

const defaultCELPCR = 13

var defaultCELHashAlgo = []crypto.Hash{crypto.SHA256, crypto.SHA1}

type tpmKeyFetcher func(rw io.ReadWriter) (*client.Key, error)
type principalIDTokenFetcher func(audience string) ([][]byte, error)

// AttestationAgent is an agent that interacts with GCE's Attestation Service
// to Verify an attestation message.
type AttestationAgent struct {
	tpm              io.ReadWriteCloser
	akFetcher        tpmKeyFetcher
	client           verifier.Client
	principalFetcher principalIDTokenFetcher
	cosCel           cel.CEL
}

// CreateAttestationAgent returns an agent capable of performing remote
// attestation using the machine's (v)TPM to GCE's Attestation Service.
// - tpm is a handle to the TPM on the instance
// - akFetcher is a func to fetch an attestation key: see go-tpm-tools/client.
// - conn is a client connection to the attestation service, typically created
//   `grpc.Dial`. It is the client's responsibility to close the connection.
func CreateAttestationAgent(tpm io.ReadWriteCloser, akFetcher tpmKeyFetcher, verifierClient verifier.Client, principalFetcher principalIDTokenFetcher) *AttestationAgent {
	return &AttestationAgent{
		tpm:              tpm,
		client:           verifierClient,
		akFetcher:        akFetcher,
		principalFetcher: principalFetcher,
	}
}

// MeasureEvent takes in a cel.Content and append it to the CEL eventlog
// under the attesation agent.
func (a *AttestationAgent) MeasureEvent(event cel.Content) error {
	return a.cosCel.AppendEvent(a.tpm, defaultCELPCR, defaultCELHashAlgo, event)
}

// Attest fetches the nonce and connection ID from the Attestation Service,
// creates an attestation message, and returns the resultant
// principalIDTokens are Metadata Server-generated ID tokens for the instance.
func (a *AttestationAgent) Attest(ctx context.Context) ([]byte, error) {
	challenge, err := a.client.CreateChallenge(ctx)
	if err != nil {
		return nil, err
	}

	principalTokens, err := a.principalFetcher(challenge.Name)
	if err != nil {
		return nil, fmt.Errorf("failed to get principal tokens: %w", err)
	}

	attestation, err := a.getAttestation(challenge.Nonce)
	if err != nil {
		return nil, err
	}

	resp, err := a.client.VerifyAttestation(ctx, verifier.VerifyAttestationRequest{
		Challenge:      challenge,
		GcpCredentials: principalTokens,
		Attestation:    attestation,
	})
	if err != nil {
		return nil, err
	}
	return resp.ClaimsToken, nil
}

func (a *AttestationAgent) getAttestation(nonce []byte) (*pb.Attestation, error) {
	ak, err := a.akFetcher(a.tpm)
	if err != nil {
		return nil, fmt.Errorf("failed to get AK: %v", err)
	}
	defer ak.Close()

	var buf bytes.Buffer
	if err := a.cosCel.EncodeCEL(&buf); err != nil {
		return nil, err
	}

	attestation, err := ak.Attest(client.AttestOpts{Nonce: nonce, CanonicalEventLog: buf.Bytes(), CertChainFetcher: http.DefaultClient})
	if err != nil {
		return nil, fmt.Errorf("failed to attest: %v", err)
	}
	return attestation, nil
}
