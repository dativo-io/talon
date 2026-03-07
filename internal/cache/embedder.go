// Package cache embedder provides BM25-style text similarity for the semantic cache (Option C).
// No raw prompt text is stored — only a serialized term vector for similarity lookup.
package cache

import (
	"encoding/json"
	"math"
	"regexp"
	"strings"
)

// termVector is a sparse term -> weight map, serialized to blob for storage.
type termVector map[string]float64

// BM25 is a pure-Go BM25-style embedder: tokenize text and produce a term vector blob.
// No external model or CGO; deterministic and suitable for exact and near-exact match caching.
type BM25 struct {
	// MinTermLen ignores tokens shorter than this (default 2).
	MinTermLen int
}

// NewBM25 returns a new BM25 embedder with default settings.
func NewBM25() *BM25 {
	return &BM25{MinTermLen: 2}
}

var nonWordRe = regexp.MustCompile(`[^\p{L}\p{N}_]+`)

// Embed tokenizes text and returns a serialized term vector (blob) for storage in the cache.
// The blob does not contain raw text; it is used only for similarity comparison via Similarity.
func (b *BM25) Embed(text string) ([]byte, error) {
	terms := b.tokenize(text)
	if len(terms) == 0 {
		return json.Marshal(termVector{})
	}
	tf := make(termVector)
	for _, t := range terms {
		tf[t]++
	}
	// Normalize to unit length for cosine similarity in [0,1]
	norm := 0.0
	for _, w := range tf {
		norm += w * w
	}
	norm = math.Sqrt(norm)
	if norm > 0 {
		for k, w := range tf {
			tf[k] = w / norm
		}
	}
	return json.Marshal(tf)
}

func (b *BM25) tokenize(text string) []string {
	lower := strings.ToLower(strings.TrimSpace(text))
	parts := nonWordRe.Split(lower, -1)
	var out []string
	for _, p := range parts {
		s := strings.TrimSpace(p)
		if len(s) >= b.MinTermLen && s != "" {
			out = append(out, s)
		}
	}
	return out
}

// Similarity computes cosine similarity between two term-vector blobs (from Embed).
// Returns a value in [0, 1]; 1 means identical vectors. Safe to use as cache.SimilarityFunc.
func (b *BM25) Similarity(queryBlob, candidateBlob []byte) (float64, error) {
	var q, c termVector
	if err := json.Unmarshal(queryBlob, &q); err != nil {
		return 0, err
	}
	if err := json.Unmarshal(candidateBlob, &c); err != nil {
		return 0, err
	}
	if len(q) == 0 || len(c) == 0 {
		return 0, nil
	}
	dot := 0.0
	for term, wq := range q {
		if wc, ok := c[term]; ok {
			dot += wq * wc
		}
	}
	// Both vectors are already L2-normalized in Embed, so ||q||=||c||=1 and cosine = dot.
	// Clamp to [0,1] for minor float noise.
	if dot < 0 {
		dot = 0
	}
	if dot > 1 {
		dot = 1
	}
	return dot, nil
}

// SimilarityFunc returns a cache.SimilarityFunc that uses this BM25 embedder.
func (b *BM25) SimilarityFunc() SimilarityFunc {
	return b.Similarity
}
