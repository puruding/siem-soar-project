// Package udm re-exports types from the shared UDM package.
// This file provides backward compatibility for the normalizer service
// while transitioning to the shared pkg/udm package.
package udm

import (
	sharedudm "github.com/siem-soar-platform/pkg/udm"
)

// Re-export types from shared package for backward compatibility.
// New code should import github.com/siem-soar-platform/pkg/udm directly.

// Type aliases for backward compatibility
type (
	// SharedUDMEvent is the UDMEvent from the shared package
	SharedUDMEvent = sharedudm.UDMEvent

	// SharedMetadata is the Metadata from the shared package
	SharedMetadata = sharedudm.Metadata

	// SharedEntity is the Entity from the shared package
	SharedEntity = sharedudm.Entity
)

// GetField provides access to the shared package's GetField function.
var GetField = sharedudm.GetField

// GetFieldAsString provides access to the shared package's GetFieldAsString function.
var GetFieldAsString = sharedudm.GetFieldAsString

// HasField provides access to the shared package's HasField function.
var HasField = sharedudm.HasField

// ToMap provides access to the shared package's ToMap function.
var ToMap = sharedudm.ToMap
