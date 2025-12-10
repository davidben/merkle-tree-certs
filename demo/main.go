package main

import (
	"bytes"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
)

var (
	flagConfig = flag.String("config", "mtc.json", "the path to the config file to generate certificates from")
	flagOutDir = flag.String("out", "out", "the path to the output directory")
)

type certificateInfo struct {
	entryConfig       *EntryConfig
	index, start, end int
	cosigners         []*CosignerConfig
	// The number of certificate for the given index.
	num int
}

func do() error {
	// Load the config.
	configBytes, err := os.ReadFile(*flagConfig)
	if err != nil {
		return err
	}
	var config CAConfig
	if err := json.Unmarshal(configBytes, &config); err != nil {
		return err
	}

	// Entries in the issuance log.
	entries := [][]byte{MarshalNullEntry()}
	// Certificates to be constructed.
	var certInfos []certificateInfo
	// Maps checkpoint sequence name to a list of certInfos indices that are
	// awaiting an end value once the next checkpoint in the sequence is
	// allocated.
	type checkpointWait struct {
		idx  int
		prev int
	}
	awaitingCheckpoint := map[string][]checkpointWait{}
	// Maps checkpoint sequence name to the latest checkpoint size.
	// Initially, all sequences are at zero, which matches the default map
	// lookup behavior.
	checkpointSeqs := map[string]int{}
	for entryConfigIdx := range config.Entries {
		entryConfig := &config.Entries[entryConfigIdx]
		repeat := 1
		if entryConfig.Repeat != 0 {
			repeat = entryConfig.Repeat
		}
		for range repeat {
			entry, err := MarshalTBSCertificateLogEntry(config.LogID, entryConfig)
			if err != nil {
				return err
			}
			entries = append(entries, entry)
			entryIdx := len(entries) - 1

			// Schedule certificates.
			for certNum, certConfig := range entryConfig.Certificates {
				info := certificateInfo{index: entryIdx, entryConfig: entryConfig, num: certNum}
				if certConfig.SubtreeEnd != 0 {
					if len(certConfig.Checkpoint) != 0 {
						return fmt.Errorf("both Checkpoint and SubtreeEnd specified in a certificate")
					}
					info.start = certConfig.SubtreeStart
					info.end = certConfig.SubtreeEnd
				} else if c := certConfig.Checkpoint; len(c) != 0 {
					// Make a note to fill in the subtree when available.
					awaitingCheckpoint[c] = append(awaitingCheckpoint[c], checkpointWait{idx: len(certInfos), prev: checkpointSeqs[c]})
				} else {
					return fmt.Errorf("neither Checkpoint nor SubtreeEnd specified in a certificate")
				}
				for _, cosignerID := range certConfig.Cosigners {
					var cosigner *CosignerConfig
					for i := range config.Cosigners {
						if bytes.Equal(config.Cosigners[i].CosignerID, cosignerID) {
							cosigner = &config.Cosigners[i]
							break
						}
					}
					if cosigner == nil {
						return fmt.Errorf("cosigner %s not found", cosignerID)
					}
					info.cosigners = append(info.cosigners, cosigner)
				}
				certInfos = append(certInfos, info)
			}

			// Update checkpoint sequences.
			for _, seq := range entryConfig.Checkpoints {
				checkpointSeqs[seq] = len(entries)
				// Fill in any certificate infos that are still awaiting
				// a checkpoint.
				for _, wait := range awaitingCheckpoint[seq] {
					// We have the checkpoint interval. Find the two subtrees
					// and use the one that includes the certificate.
					start1, end1, start2, end2, err := SubtreesForInterval(wait.prev, len(entries))
					if err != nil {
						return err
					}
					if certInfos[wait.idx].index < end1 {
						certInfos[wait.idx].start = start1
						certInfos[wait.idx].end = end1
					} else {
						certInfos[wait.idx].start = start2
						certInfos[wait.idx].end = end2
					}
				}
				delete(awaitingCheckpoint, seq)
			}
		}
	}

	for seq := range awaitingCheckpoint {
		return fmt.Errorf("certificate required checkpoint sequence %q, but no checkpoint in sequence defined", seq)
	}

	issuanceLog := NewMerkleTree(entries)

	// Construct certificates.
	if err := os.MkdirAll(*flagOutDir, 0750); err != nil {
		log.Fatal(err)
	}
	for _, info := range certInfos {
		// A real CA would not generate fresh cosignatures for every certificate.
		// This tool does because it's a bit flexible
		cert, err := CreateCertificate(issuanceLog, config.LogID, info.cosigners, info.entryConfig, info.index, info.start, info.end)
		if err != nil {
			return err
		}
		certPath := filepath.Join(*flagOutDir, fmt.Sprintf("cert_%d_%d.pem", info.index, info.num))
		certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert})
		if err := os.WriteFile(certPath, certPEM, 0644); err != nil {
			return err
		}
	}

	// TODO: Also write out tiles and a checkpoint in tlog-checkpoint format.
	return nil
}

func main() {
	flag.Parse()
	if err := do(); err != nil {
		fmt.Fprintf(os.Stderr, "Error generating certificates: %s\n", err)
		os.Exit(1)
	}
}
