package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"testing"
)

func challengeMap(v int, target string) map[string]json.RawMessage {
	return map[string]json.RawMessage{"challenge_version": json.RawMessage(fmt.Sprint(v)), "algorithm": json.RawMessage(`"SHA-256"`), "salt": json.RawMessage(`"test-salt"`), "challenge": json.RawMessage(`"` + target + `"`), "timeout": json.RawMessage(`1000`)}
}
func TestSHAChallengeVersions(t *testing.T) {
	for _, v := range []int{2, 3} {
		t.Run(fmt.Sprint(v), func(t *testing.T) {
			h := sha256.Sum256([]byte("test-salt4321"))
			if v == 3 {
				h[31], h[28] = h[28], h[31]
				h[30], h[29] = h[29], h[30]
			}
			n, _, e := solveChallenge(context.Background(), challengeMap(v, hex.EncodeToString(h[:])))
			if e != nil || n.(int) != 4321 {
				t.Fatal(n, e)
			}
		})
	}
}
func TestFactorChallenge(t *testing.T) {
	c := map[string]json.RawMessage{"challenge_version": json.RawMessage(`1`), "low": json.RawMessage(`10`), "high": json.RawMessage(`30`), "parts": json.RawMessage(`3`), "result": json.RawMessage(`"7429"`)}
	n, _, e := solveChallenge(context.Background(), c)
	if e != nil {
		t.Fatal(e)
	}
	a := n.([]int)
	if len(a) != 3 || a[0]*a[1]*a[2] != 7429 {
		t.Fatal(a)
	}
}
func TestChallengeRejectsUnknownVersion(t *testing.T) {
	if _, _, e := solveChallenge(context.Background(), challengeMap(99, "none")); e == nil {
		t.Fatal("unknown challenge accepted")
	}
}
func TestChallengeCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, e := solveChallenge(ctx, challengeMap(3, "none")); e == nil {
		t.Fatal("cancel ignored")
	}
}
