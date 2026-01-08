package main

import (
	"crypto/sha256"
	"fmt"
	"math/bits"
)

const HashSize = sha256.Size

type HashValue = [HashSize]byte

func HashLeaf(b []byte) HashValue {
	h := sha256.New()
	h.Write([]byte{0})
	h.Write(b)
	var ret HashValue
	h.Sum(ret[:0])
	return ret
}

func HashNode(left, right *HashValue) HashValue {
	h := sha256.New()
	h.Write([]byte{1})
	h.Write((*left)[:])
	h.Write((*right)[:])
	var ret HashValue
	h.Sum(ret[:0])
	return ret
}

func IsValidSubtree(start, end int) bool {
	if 0 > start || start >= end {
		return false
	}
	ceil := uint(1) << (bits.UintSize - bits.LeadingZeros(uint(end-start-1)))
	return uint(start)&(ceil-1) == 0
}

type MerkleTree struct {
	// levels[i][j] has MTH(
	levels [][]HashValue
}

func NewMerkleTree(entries [][]byte) *MerkleTree {
	log := &MerkleTree{}
	// Hash level 0.
	level := make([]HashValue, len(entries))
	for i, entry := range entries {
		level[i] = HashLeaf(entry)
	}
	log.levels = append(log.levels, level)
	// Compute all subsequent levels.
	for {
		last := log.levels[len(log.levels)-1]
		if len(last) < 2 {
			break
		}
		level = make([]HashValue, len(last)/2)
		for i := range level {
			level[i] = HashNode(&last[2*i], &last[2*i+1])
		}
		log.levels = append(log.levels, level)
	}
	return log
}

func (mt *MerkleTree) Size() int { return len(mt.levels[0]) }

func (mt *MerkleTree) SubtreeHash(start, end int) (HashValue, error) {
	if !IsValidSubtree(start, end) {
		return HashValue{}, fmt.Errorf("invalid subtree: [%d, %d)", start, end)
	}
	if end > mt.Size() {
		return HashValue{}, fmt.Errorf("subtree [%d, %d) contains more elements than tree of size %d", start, end, mt.Size())
	}
	// Start at the largest complete subtree on the right edge.
	last := end - 1
	level := bits.TrailingZeros(^uint(last - start))
	start >>= level
	last >>= level
	ret := mt.levels[level][last]
	// Invariant: ret is SubtreeHash(last<<level, end).
	// Iterate up until we get the desired subtree.
	for start < last {
		if last&1 == 1 {
			ret = HashNode(&mt.levels[level][last-1], &ret)
		}
		level++
		start >>= 1
		last >>= 1
	}
	return ret, nil
}

func (mt *MerkleTree) SubtreeInclusionProof(index, start, end int) ([]byte, error) {
	if !IsValidSubtree(start, end) {
		return nil, fmt.Errorf("invalid subtree: [%d, %d)", start, end)
	}
	if end > mt.Size() {
		return nil, fmt.Errorf("subtree [%d, %d) contains more elements than tree of size %d", start, end, mt.Size())
	}
	if start > index || index >= end {
		return nil, fmt.Errorf("index %d not contained in subtree [%d, %d)", index, start, end)
	}
	var proof []byte
	var level int
	last := end - 1
	for start < last {
		// Provide the neighbor node, if it exists.
		neighbor := index ^ 1
		if neighbor < last {
			// The neighbor is complete, so we can look it up directly.
			proof = append(proof, mt.levels[level][neighbor][:]...)
		} else if neighbor == last {
			// The neighbor is on the right edge and may not be complete.
			h, err := mt.SubtreeHash(last<<level, end)
			if err != nil {
				panic(err) // This should not happen.
			}
			proof = append(proof, h[:]...)
		}
		level++
		start >>= 1
		index >>= 1
		last >>= 1
	}
	return proof, nil
}

func SubtreesForInterval(start, end int) (start1, end1, start2, end2 int, err error) {
	if 0 > start || start >= end {
		err = fmt.Errorf("invalid interval [%d, %d)", start, end)
		return
	}
	if end-start == 1 {
		start1 = start
		start2 = start
		end1 = end
		end2 = end
		return
	}
	last := end - 1
	// Find where start and last's tree paths diverge. The two
	// subtrees will be on either side of the split.
	split := bits.Len(uint(start^last)) - 1
	mask := (1 << split) - 1
	mid := last & ^mask
	// Maximize the left endpoint. This is just before start's
	// path leaves the right edge of its new subtree.
	leftSplit := bits.Len(uint(^start & mask))
	start1 = start & ^((1 << leftSplit) - 1)
	end1 = mid
	start2 = mid
	end2 = end
	return
}
