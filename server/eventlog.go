package server

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/google/go-attestation/attest"
	"github.com/google/go-tpm-tools/cel"
	pb "github.com/google/go-tpm-tools/proto/attest"
	tpmpb "github.com/google/go-tpm-tools/proto/tpm"
	"github.com/google/go-tpm/tpm2"
)

// parsePCClientEventLog parses a raw event log and replays the parsed event
// log against the given PCR values. It returns the corresponding MachineState
// containing the events verified by particular PCR indexes/digests. It returns
// an error if the replay for any PCR index does not match the provided value.
//
// The returned MachineState may be a partial MachineState where fields can be
// the zero value. In this case, an error of type MachineStateError will be
// returned. Callers can inspect individual parsing errors by examining
// `MachineStateError.Errors`.
//
// It is the caller's responsibility to ensure that the passed PCR values can be
// trusted. Users can establish trust in PCR values by either calling
// client.ReadPCRs() themselves or by verifying the values via a PCR quote.
func parsePCClientEventLog(rawEventLog []byte, pcrs *tpmpb.PCRs, loader Bootloader) (*pb.MachineState, error) {
	var errors []error
	events, err := parseReplayHelper(rawEventLog, pcrs)
	if err != nil {
		return nil, createGroupedError("", []error{err})
	}
	// error is already checked in convertToAttestPcrs
	cryptoHash, _ := tpm2.Algorithm(pcrs.GetHash()).Hash()

	rawEvents := convertToPbEvents(cryptoHash, events)
	platform, err := getPlatformState(cryptoHash, rawEvents)
	if err != nil {
		errors = append(errors, err)
	}
	sbState, err := getSecureBootState(events)
	if err != nil {
		errors = append(errors, err)
	}

	var grub *pb.GrubState
	if loader == GRUB {
		grub, err = getGrubState(cryptoHash, rawEvents)
		if err != nil {
			errors = append(errors, err)
		}
	}

	return &pb.MachineState{
		Platform:   platform,
		SecureBoot: sbState,
		RawEvents:  rawEvents,
		Hash:       pcrs.GetHash(),
		Grub:       grub,
	}, createGroupedError("failed to fully parse MachineState:", errors)
}

func parseCanonicalEventLog(rawCanonicalEventLog []byte, pcrs *tpmpb.PCRs) (*pb.MachineState, error) {
	decodedCEL, err := cel.DecodeToCEL(bytes.NewBuffer(rawCanonicalEventLog))
	if err != nil {
		return nil, err
	}
	// Validate the COS event log first.
	if err := decodedCEL.Replay(pcrs); err != nil {
		return nil, err
	}

	cosState, err := getVerifiedCosState(decodedCEL, pcrs)
	if err != nil {
		return nil, err
	}

	return &pb.MachineState{
		Cos: cosState,
	}, err
}

func contains(set [][]byte, value []byte) bool {
	for _, setItem := range set {
		if bytes.Equal(value, setItem) {
			return true
		}
	}
	return false
}

func getVerifiedCosState(coscel cel.CEL, pcrs *tpmpb.PCRs) (*pb.AttestedCosState, error) {
	cosState := &pb.AttestedCosState{}
	cosState.Container = &pb.ContainerState{}
	cosState.Container.Args = make([]string, 0)
	cosState.Container.EnvVars = make(map[string]string)
	cosState.Container.OverriddenEnvVars = make(map[string]string)

	for _, record := range coscel.Records {
		// ignore non COS CEL events
		if !record.Content.IsCosTlv() {
			continue
		}

		cosTlv, err := record.Content.ParseToCosTlv()
		if err != nil {
			return nil, err
		}

		// verify digests for the cos cel content
		if err := cel.VerifyDigests(cosTlv, record.Digests); err != nil {
			return nil, err
		}

		switch cosTlv.EventType {
		case cel.ImageRefType:
			cosState.Container.ImageReference = string(cosTlv.EventContent)

		case cel.ImageDigestType:
			cosState.Container.ImageDigest = string(cosTlv.EventContent)

		case cel.RestartPolicyType:
			restartPolicy, ok := pb.RestartPolicy_value[string(cosTlv.EventContent)]
			if !ok {
				return nil, fmt.Errorf("unknown restart policy in COS eventlog: %s", string(cosTlv.EventContent))
			}
			cosState.Container.RestartPolicy = pb.RestartPolicy(restartPolicy)

		case cel.ImageIDType:
			cosState.Container.ImageId = string(cosTlv.EventContent)

		case cel.EnvVarType:
			envName, envVal, err := cel.ParseEnvVar(string(cosTlv.EventContent))
			if err != nil {
				return nil, err
			}
			cosState.Container.EnvVars[envName] = envVal

		case cel.ArgType:
			cosState.Container.Args = append(cosState.Container.Args, string(cosTlv.EventContent))

		case cel.OverrideArgType:
			cosState.Container.OverriddenArgs = append(cosState.Container.OverriddenArgs, string(cosTlv.EventContent))

		case cel.OverrideEnvType:
			envName, envVal, err := cel.ParseEnvVar(string(cosTlv.EventContent))
			if err != nil {
				return nil, err
			}
			cosState.Container.OverriddenEnvVars[envName] = envVal
		}

	}
	return cosState, nil
}

func getPlatformState(hash crypto.Hash, events []*pb.Event) (*pb.PlatformState, error) {
	// We pre-compute the separator event hash, and check if the event type has
	// been modified. We only trust events that come before a valid separator.
	hasher := hash.New()
	// From the PC Client Firmware Profile spec, on the separator event:
	// The event field MUST contain the hex value 00000000h or FFFFFFFFh.
	separatorData := [][]byte{{0, 0, 0, 0}, {0xff, 0xff, 0xff, 0xff}}
	separatorDigests := make([][]byte, 0, len(separatorData))
	for _, value := range separatorData {
		hasher.Write(value)
		separatorDigests = append(separatorDigests, hasher.Sum(nil))
	}

	var versionString []byte
	var nonHostInfo []byte
	for _, event := range events {
		index := event.GetPcrIndex()
		if index != 0 {
			continue
		}
		evtType := event.GetUntrustedType()

		// Make sure we have a valid separator event, we check any event that
		// claims to be a Separator or "looks like" a separator to prevent
		// certain vulnerabilities in event parsing. For more info see:
		// https://github.com/google/go-attestation/blob/master/docs/event-log-disclosure.md
		if (evtType == Separator) || contains(separatorDigests, event.GetDigest()) {
			if evtType != Separator {
				return nil, fmt.Errorf("PCR%d event contains separator data but non-separator type %d", index, evtType)
			}
			if !event.GetDigestVerified() {
				return nil, fmt.Errorf("unverified separator digest for PCR%d", index)
			}
			if !contains(separatorData, event.GetData()) {
				return nil, fmt.Errorf("invalid separator data for PCR%d", index)
			}
			// Don't trust any PCR0 events after the separator
			break
		}

		if evtType == SCRTMVersion {
			if !event.GetDigestVerified() {
				return nil, fmt.Errorf("invalid SCRTM version event for PCR%d", index)
			}
			versionString = event.GetData()
		}

		if evtType == NonhostInfo {
			if !event.GetDigestVerified() {
				return nil, fmt.Errorf("invalid Non-Host info event for PCR%d", index)
			}
			nonHostInfo = event.GetData()
		}
	}

	state := &pb.PlatformState{}
	if gceVersion, err := ConvertSCRTMVersionToGCEFirmwareVersion(versionString); err == nil {
		state.Firmware = &pb.PlatformState_GceVersion{GceVersion: gceVersion}
	} else {
		state.Firmware = &pb.PlatformState_ScrtmVersionId{ScrtmVersionId: versionString}
	}

	if tech, err := ParseGCENonHostInfo(nonHostInfo); err == nil {
		state.Technology = tech
	}

	return state, nil
}

// Separate helper function so we can use attest.ParseSecurebootState without
// needing to reparse the entire event log.
func parseReplayHelper(rawEventLog []byte, pcrs *tpmpb.PCRs) ([]attest.Event, error) {
	attestPcrs, err := convertToAttestPcrs(pcrs)
	if err != nil {
		return nil, fmt.Errorf("received bad PCR proto: %v", err)
	}
	eventLog, err := attest.ParseEventLog(rawEventLog)
	if err != nil {
		return nil, fmt.Errorf("failed to parse event log: %v", err)
	}
	events, err := eventLog.Verify(attestPcrs)
	if err != nil {
		return nil, fmt.Errorf("failed to replay event log: %v", err)
	}
	return events, nil
}

func convertToAttestPcrs(pcrProto *tpmpb.PCRs) ([]attest.PCR, error) {
	if len(pcrProto.GetPcrs()) == 0 {
		return nil, errors.New("no PCRs to convert")
	}
	hash := tpm2.Algorithm(pcrProto.GetHash())
	cryptoHash, err := hash.Hash()
	if err != nil {
		return nil, err
	}

	attestPcrs := make([]attest.PCR, 0, len(pcrProto.GetPcrs()))
	for index, digest := range pcrProto.GetPcrs() {
		attestPcrs = append(attestPcrs, attest.PCR{
			Index:     int(index),
			Digest:    digest,
			DigestAlg: cryptoHash,
		})
	}
	return attestPcrs, nil
}

func convertToPbEvents(hash crypto.Hash, events []attest.Event) []*pb.Event {
	pbEvents := make([]*pb.Event, len(events))
	for i, event := range events {
		hasher := hash.New()
		hasher.Write(event.Data)
		digest := hasher.Sum(nil)

		pbEvents[i] = &pb.Event{
			PcrIndex:       uint32(event.Index),
			UntrustedType:  uint32(event.Type),
			Data:           event.Data,
			Digest:         event.Digest,
			DigestVerified: bytes.Equal(digest, event.Digest),
		}
	}
	return pbEvents
}

func convertToPbDatabase(certs []x509.Certificate, hashes [][]byte) *pb.Database {
	protoCerts := make([]*pb.Certificate, 0, len(certs))
	for _, cert := range certs {
		wkEnum, err := matchWellKnown(cert)
		var pbCert pb.Certificate
		if err == nil {
			pbCert.Representation = &pb.Certificate_WellKnown{WellKnown: wkEnum}
		} else {
			pbCert.Representation = &pb.Certificate_Der{Der: cert.Raw}
		}
		protoCerts = append(protoCerts, &pbCert)
	}
	return &pb.Database{
		Certs:  protoCerts,
		Hashes: hashes,
	}
}

func matchWellKnown(cert x509.Certificate) (pb.WellKnownCertificate, error) {
	if bytes.Equal(WindowsProductionPCA2011Cert, cert.Raw) {
		return pb.WellKnownCertificate_MS_WINDOWS_PROD_PCA_2011, nil
	}
	if bytes.Equal(MicrosoftUEFICA2011Cert, cert.Raw) {
		return pb.WellKnownCertificate_MS_THIRD_PARTY_UEFI_CA_2011, nil
	}
	return pb.WellKnownCertificate_UNKNOWN, errors.New("failed to find matching well known certificate")
}

func getSecureBootState(attestEvents []attest.Event) (*pb.SecureBootState, error) {
	attestSbState, err := attest.ParseSecurebootState(attestEvents)
	if err != nil {
		return nil, fmt.Errorf("failed to parse SecureBootState: %v", err)
	}
	if len(attestSbState.PreSeparatorAuthority) != 0 {
		return nil, fmt.Errorf("event log contained %v pre-separator authorities, which are not expected or supported", len(attestSbState.PreSeparatorAuthority))
	}
	return &pb.SecureBootState{
		Enabled:   attestSbState.Enabled,
		Db:        convertToPbDatabase(attestSbState.PermittedKeys, attestSbState.PermittedHashes),
		Dbx:       convertToPbDatabase(attestSbState.ForbiddenKeys, attestSbState.ForbiddenHashes),
		Authority: convertToPbDatabase(attestSbState.PostSeparatorAuthority, nil),
	}, nil
}

func getGrubState(hash crypto.Hash, events []*pb.Event) (*pb.GrubState, error) {
	var files []*pb.GrubFile
	var commands []string
	for idx, event := range events {
		index := event.GetPcrIndex()
		if index != 8 && index != 9 {
			continue
		}

		if event.GetUntrustedType() != IPL {
			return nil, fmt.Errorf("invalid event type for PCR%d, expected EV_IPL", index)
		}

		if index == 9 {
			files = append(files, &pb.GrubFile{Digest: event.GetDigest(),
				UntrustedFilename: event.GetData()})
		} else if index == 8 {
			hasher := hash.New()
			suffixAt := -1
			rawData := event.GetData()
			for _, prefix := range validPrefixes {
				if bytes.HasPrefix(rawData, prefix) {
					suffixAt = len(prefix)
					break
				}
			}
			if suffixAt == -1 {
				return nil, fmt.Errorf("invalid prefix seen for PCR%d event: %s", index, rawData)
			}
			hasher.Write(rawData[suffixAt : len(rawData)-1])
			if !bytes.Equal(event.Digest, hasher.Sum(nil)) {
				// Older GRUBs measure "grub_cmd " with the null terminator.
				// However, "grub_kernel_cmdline " measurements also ignore the null terminator.
				hasher.Reset()
				hasher.Write(rawData[suffixAt:])
				if !bytes.Equal(event.Digest, hasher.Sum(nil)) {
					return nil, fmt.Errorf("invalid digest seen for GRUB event log in event %d: %s", idx, hex.EncodeToString(event.Digest))
				}
			}
			hasher.Reset()
			commands = append(commands, string(rawData))
		}
	}
	if len(files) == 0 && len(commands) == 0 {
		return nil, errors.New("no GRUB measurements found")
	}
	return &pb.GrubState{Files: files, Commands: commands}, nil
}
