//go:build !linux || !amd64

package ebpf

type PolicyManager struct{}

func NewPolicyManager() *PolicyManager                                        { return &PolicyManager{} }
func (pm *PolicyManager) SetGeoSitePolicy(siteCode uint8, mark uint32) error  { return nil }
func (pm *PolicyManager) SetGeoIPPolicy(countryCode uint8, mark uint32) error { return nil }
func (pm *PolicyManager) ApplyDefaultsFromEnv()                               {}
