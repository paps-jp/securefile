package service

import (
	"fmt"
	"math"
	"time"
)

// Config holds the operational limits of one service instance.
type Config struct {
	// BlobRoot is the directory holding encrypted file bodies.
	BlobRoot string

	// MaxFiles caps how many files one share may contain.
	MaxFiles int
	// MaxTotalBytes is the absolute ceiling on one share's combined size. The
	// effective per-share limit is usually smaller, computed from the chosen
	// retention and download count (see MaxUploadBytes).
	MaxTotalBytes int64
	// MaxDays caps the retention a user may request.
	MaxDays int
	// MaxDownloads caps the download allowance a user may request.
	MaxDownloads int

	// The allowed upload size shrinks as the requested retention or download
	// count grows, because both raise the resource cost of a share (storage
	// over time, and bandwidth per download). The limit is interpolated
	// geometrically between these anchors and the smaller of the two wins.
	SizeAtMinDays      int64 // allowed size at 1 day
	SizeAtMaxDays      int64 // allowed size at MaxDays
	SizeAtMinDownloads int64 // allowed size at 1 download
	SizeAtMaxDownloads int64 // allowed size at MaxDownloads

	// PartSize is the upload part size advertised to clients. It must be a
	// multiple of the encryption chunk size.
	PartSize int64

	// UploadTTL is how long an interrupted upload can be resumed.
	UploadTTL time.Duration
	// DownloadTTL is how long a unlocked session stays valid.
	DownloadTTL time.Duration

	// DiskQuotaBytes is the storage budget reported on the status panel and
	// enforced before accepting a new upload. Zero disables the check.
	DiskQuotaBytes int64
}

// DefaultConfig returns limits suitable for the public instance.
func DefaultConfig(blobRoot string) Config {
	return Config{
		BlobRoot:      blobRoot,
		MaxFiles:      100,
		MaxTotalBytes: 10 << 30, // 10 GiB absolute ceiling
		MaxDays:       100,
		MaxDownloads:  500,
		PartSize:      8 << 20, // 8 MiB — 8 encryption chunks
		UploadTTL:     24 * time.Hour,
		DownloadTTL:   30 * time.Minute,

		// 1 day → 10 GiB, 100 days → 500 MiB (and likewise for downloads).
		SizeAtMinDays:      10 << 30,
		SizeAtMaxDays:      500 << 20,
		SizeAtMinDownloads: 10 << 30,
		SizeAtMaxDownloads: 500 << 20,
	}
}

// MaxUploadBytes returns the largest total share size allowed for the given
// retention and download count. Each dimension is interpolated geometrically
// between its anchors, and the smaller limit applies — a share that is both
// long-lived and widely downloaded is held to the tighter of the two.
func (c Config) MaxUploadBytes(days, downloads int) int64 {
	byDays := geomLimit(days, 1, c.SizeAtMinDays, c.MaxDays, c.SizeAtMaxDays)
	byDownloads := geomLimit(downloads, 1, c.SizeAtMinDownloads, c.MaxDownloads, c.SizeAtMaxDownloads)
	return min(min(byDays, byDownloads), c.MaxTotalBytes)
}

// geomLimit interpolates a size between (x0,y0) and (x1,y1) on a log scale, so
// the curve is a smooth inverse rather than a straight line, and clamps x to
// the anchor range.
func geomLimit(x, x0 int, y0 int64, x1 int, y1 int64) int64 {
	if x1 == x0 {
		return y0
	}
	if x <= x0 {
		return y0
	}
	if x >= x1 {
		return y1
	}
	t := float64(x-x0) / float64(x1-x0)
	v := float64(y0) * math.Pow(float64(y1)/float64(y0), t)
	return int64(v)
}

// Validate reports configuration that would misbehave at runtime rather than
// letting it fail later on a user's upload.
func (c Config) Validate() error {
	if c.BlobRoot == "" {
		return fmt.Errorf("service: BlobRoot must be set")
	}
	if c.MaxFiles < 1 {
		return fmt.Errorf("service: MaxFiles must be at least 1, got %d", c.MaxFiles)
	}
	if c.MaxTotalBytes < 1 {
		return fmt.Errorf("service: MaxTotalBytes must be positive, got %d", c.MaxTotalBytes)
	}
	if c.MaxDays < 1 {
		return fmt.Errorf("service: MaxDays must be at least 1, got %d", c.MaxDays)
	}
	if c.MaxDownloads < 1 {
		return fmt.Errorf("service: MaxDownloads must be at least 1, got %d", c.MaxDownloads)
	}
	// Parts that are not whole chunks cannot be resumed from, so this is a
	// correctness constraint rather than a tuning preference.
	if c.PartSize <= 0 || c.PartSize%chunkSize != 0 {
		return fmt.Errorf("service: PartSize must be a positive multiple of %d, got %d", chunkSize, c.PartSize)
	}
	if c.UploadTTL <= 0 {
		return fmt.Errorf("service: UploadTTL must be positive, got %s", c.UploadTTL)
	}
	if c.DownloadTTL <= 0 {
		return fmt.Errorf("service: DownloadTTL must be positive, got %s", c.DownloadTTL)
	}
	return nil
}
