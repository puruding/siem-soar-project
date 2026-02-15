// Package identifier provides asset identification logic.
package identifier

import (
	"context"
	"log/slog"
	"net"
	"regexp"
	"strings"
	"time"

	"github.com/siem-soar-platform/services/asset-registry/internal/model"
	"github.com/siem-soar-platform/services/asset-registry/internal/repository"
)

// Resolver resolves asset identifiers to assets.
type Resolver struct {
	repo   repository.AssetRepository
	logger *slog.Logger
}

// NewResolver creates a new identifier resolver.
func NewResolver(repo repository.AssetRepository, logger *slog.Logger) *Resolver {
	return &Resolver{
		repo:   repo,
		logger: logger.With("component", "identifier-resolver"),
	}
}

// Resolve attempts to identify an asset from various identifiers.
func (r *Resolver) Resolve(ctx context.Context, req *model.IdentifyAssetRequest) (*model.IdentifyAssetResponse, error) {
	response := &model.IdentifyAssetResponse{
		Found: false,
	}

	// Try identifiers in order of reliability
	identifiers := r.buildIdentifierList(req)

	for _, ident := range identifiers {
		asset, err := r.repo.LookupByIdentifier(ctx, ident.Type, ident.Value)
		if err != nil {
			r.logger.Debug("lookup failed", "type", ident.Type, "value", ident.Value, "error", err)
			continue
		}
		if asset != nil {
			response.Found = true
			response.Asset = asset
			response.MatchedBy = ident.Type
			response.Confidence = ident.Confidence
			return response, nil
		}
	}

	// If not found, try fuzzy matching on hostname
	if req.Hostname != "" {
		suggestions, err := r.fuzzyMatch(ctx, req.Hostname)
		if err == nil && len(suggestions) > 0 {
			response.Suggestions = suggestions
		}
	}

	return response, nil
}

// identifierEntry represents a prioritized identifier.
type identifierEntry struct {
	Type       string
	Value      string
	Confidence float64
}

func (r *Resolver) buildIdentifierList(req *model.IdentifyAssetRequest) []identifierEntry {
	var identifiers []identifierEntry

	// Agent ID - highest confidence
	if req.AgentID != "" {
		identifiers = append(identifiers, identifierEntry{
			Type:       "agent_id",
			Value:      req.AgentID,
			Confidence: 0.99,
		})
	}

	// MAC address - very high confidence (unique hardware identifier)
	if req.MAC != "" {
		normalizedMAC := normalizeMAC(req.MAC)
		identifiers = append(identifiers, identifierEntry{
			Type:       "mac",
			Value:      normalizedMAC,
			Confidence: 0.95,
		})
	}

	// FQDN - high confidence
	if req.FQDN != "" {
		identifiers = append(identifiers, identifierEntry{
			Type:       "fqdn",
			Value:      strings.ToLower(req.FQDN),
			Confidence: 0.90,
		})
	}

	// Hostname - medium confidence
	if req.Hostname != "" {
		identifiers = append(identifiers, identifierEntry{
			Type:       "hostname",
			Value:      strings.ToLower(req.Hostname),
			Confidence: 0.85,
		})
	}

	// IP address - lower confidence (can change)
	if req.IP != "" {
		// Validate IP
		if ip := net.ParseIP(req.IP); ip != nil {
			// Check if private IP
			confidence := 0.70
			if isPrivateIP(ip) {
				confidence = 0.75 // Private IPs are slightly more stable
			}
			identifiers = append(identifiers, identifierEntry{
				Type:       "ip",
				Value:      ip.String(),
				Confidence: confidence,
			})
		}
	}

	return identifiers
}

func (r *Resolver) fuzzyMatch(ctx context.Context, hostname string) ([]*model.Asset, error) {
	// Search for similar hostnames
	filter := &model.AssetFilter{
		Hostname: hostname,
		Limit:    5,
	}

	result, err := r.repo.List(ctx, filter)
	if err != nil {
		return nil, err
	}

	return result.Assets, nil
}

// normalizeMAC normalizes a MAC address to lowercase with colons.
func normalizeMAC(mac string) string {
	// Remove common separators
	mac = strings.ToLower(mac)
	mac = strings.ReplaceAll(mac, "-", "")
	mac = strings.ReplaceAll(mac, ":", "")
	mac = strings.ReplaceAll(mac, ".", "")

	// Reformat with colons
	if len(mac) == 12 {
		return mac[0:2] + ":" + mac[2:4] + ":" + mac[4:6] + ":" + mac[6:8] + ":" + mac[8:10] + ":" + mac[10:12]
	}
	return mac
}

// isPrivateIP checks if an IP is in a private range.
func isPrivateIP(ip net.IP) bool {
	privateBlocks := []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"fc00::/7",
	}

	for _, cidr := range privateBlocks {
		_, block, _ := net.ParseCIDR(cidr)
		if block.Contains(ip) {
			return true
		}
	}
	return false
}

// ValidateIP validates an IP address.
func ValidateIP(ip string) bool {
	return net.ParseIP(ip) != nil
}

// ValidateMAC validates a MAC address.
func ValidateMAC(mac string) bool {
	// Common MAC formats
	patterns := []string{
		`^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$`,          // 00:11:22:33:44:55 or 00-11-22-33-44-55
		`^([0-9A-Fa-f]{4}\.){2}([0-9A-Fa-f]{4})$`,            // 0011.2233.4455
		`^[0-9A-Fa-f]{12}$`,                                  // 001122334455
	}

	for _, pattern := range patterns {
		matched, _ := regexp.MatchString(pattern, mac)
		if matched {
			return true
		}
	}
	return false
}

// ValidateHostname validates a hostname.
func ValidateHostname(hostname string) bool {
	if len(hostname) == 0 || len(hostname) > 253 {
		return false
	}

	// Check for valid hostname pattern
	pattern := `^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$`
	matched, _ := regexp.MatchString(pattern, hostname)
	return matched
}

// UpdateIdentifierLastSeen updates the last seen timestamp for identifiers.
func (r *Resolver) UpdateIdentifierLastSeen(ctx context.Context, assetID string, identifiers []string) error {
	for _, ident := range identifiers {
		parts := strings.SplitN(ident, ":", 2)
		if len(parts) != 2 {
			continue
		}

		identifier := &model.AssetIdentifier{
			AssetID:    assetID,
			Type:       parts[0],
			Value:      parts[1],
			LastSeenAt: time.Now(),
		}

		if err := r.repo.AddIdentifier(ctx, assetID, identifier); err != nil {
			r.logger.Debug("failed to update identifier last seen",
				"asset_id", assetID,
				"identifier", ident,
				"error", err,
			)
		}
	}
	return nil
}

// BulkResolve resolves multiple identifier requests.
func (r *Resolver) BulkResolve(ctx context.Context, requests []*model.IdentifyAssetRequest) ([]*model.IdentifyAssetResponse, error) {
	responses := make([]*model.IdentifyAssetResponse, len(requests))

	for i, req := range requests {
		resp, err := r.Resolve(ctx, req)
		if err != nil {
			responses[i] = &model.IdentifyAssetResponse{
				Found: false,
			}
			continue
		}
		responses[i] = resp
	}

	return responses, nil
}
