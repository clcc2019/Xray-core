package router

import (
	"regexp"
	"strings"

	"github.com/xtls/xray-core/app/router/ebpf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/strmatcher"
	"github.com/xtls/xray-core/features/routing"
)

type Condition interface {
	Apply(ctx routing.Context) bool
}

type ConditionChan []Condition

func NewConditionChan() *ConditionChan {
	var condChan ConditionChan = make([]Condition, 0, 8)
	return &condChan
}

func (v *ConditionChan) Add(cond Condition) *ConditionChan {
	*v = append(*v, cond)
	return v
}

// Apply applies all conditions registered in this chan.
func (v *ConditionChan) Apply(ctx routing.Context) bool {
	for _, cond := range *v {
		if !cond.Apply(ctx) {
			return false
		}
	}
	return true
}

func (v *ConditionChan) Len() int {
	return len(*v)
}

var matcherTypeMap = map[Domain_Type]strmatcher.Type{
	Domain_Plain:  strmatcher.Substr,
	Domain_Regex:  strmatcher.Regex,
	Domain_Domain: strmatcher.Domain,
	Domain_Full:   strmatcher.Full,
}

func domainToMatcher(domain *Domain) (strmatcher.Matcher, error) {
	matcherType, f := matcherTypeMap[domain.Type]
	if !f {
		return nil, errors.New("unsupported domain type", domain.Type)
	}

	matcher, err := matcherType.New(domain.Value)
	if err != nil {
		return nil, errors.New("failed to create domain matcher").Base(err)
	}

	return matcher, nil
}

type DomainMatcher struct {
	matchers    strmatcher.IndexMatcher
	ebpfMatcher *ebpf.EBpfGeoSiteMatcher
	ebpfEnabled bool
}

func NewMphMatcherGroup(domains []*Domain) (*DomainMatcher, error) {
	g := strmatcher.NewMphMatcherGroup()
	for _, d := range domains {
		matcherType, f := matcherTypeMap[d.Type]
		if !f {
			return nil, errors.New("unsupported domain type", d.Type)
		}
		_, err := g.AddPattern(d.Value, matcherType)
		if err != nil {
			return nil, err
		}
	}
	g.Build()

	// 初始化eBPF匹配器
	errors.LogInfo(nil, "NewMphMatcherGroup: Initializing eBPF GeoSite matcher for ", len(domains), " domains")
	ebpfMatcher, err := ebpf.NewEBpfGeoSiteMatcher("default", false)
	if err != nil {
		errors.LogInfo(nil, "NewMphMatcherGroup: Failed to initialize eBPF GeoSite matcher: ", err)
	} else {
		errors.LogInfo(nil, "NewMphMatcherGroup: eBPF GeoSite matcher initialized successfully")
	}

	dm := &DomainMatcher{
		matchers:    g,
		ebpfMatcher: ebpfMatcher,
		ebpfEnabled: ebpfMatcher != nil && ebpfMatcher.IsEnabled(),
	}

	// 将域名规则添加到eBPF匹配器
	if dm.ebpfEnabled {
		for i, d := range domains {
			siteCode := uint8(i + 1)
			switch d.Type {
			case Domain_Full:
				ebpfMatcher.AddDomain(d.Value, siteCode)
			case Domain_Plain:
				ebpfMatcher.AddKeyword(d.Value, siteCode)
			case Domain_Regex:
				ebpfMatcher.AddRegex(d.Value, siteCode)
			case Domain_Domain:
				ebpfMatcher.AddDomain(d.Value, siteCode)
			}
		}
	}

	return dm, nil
}

func NewDomainMatcher(domains []*Domain) (*DomainMatcher, error) {
	g := new(strmatcher.MatcherGroup)
	for _, d := range domains {
		m, err := domainToMatcher(d)
		if err != nil {
			return nil, err
		}
		g.Add(m)
	}

	// 初始化动态eBPF匹配器（智能缓存模式）
	errors.LogInfo(nil, "NewDomainMatcher: Initializing dynamic eBPF GeoSite matcher (smart caching mode)")
	ebpfMatcher, err := ebpf.NewEBpfGeoSiteMatcher("dynamic", true) // 启用动态模式
	if err != nil {
		errors.LogInfo(nil, "NewDomainMatcher: Failed to initialize dynamic eBPF GeoSite matcher: ", err)
	} else {
		errors.LogInfo(nil, "NewDomainMatcher: Dynamic eBPF GeoSite matcher initialized successfully")
	}

	dm := &DomainMatcher{
		matchers:    g,
		ebpfMatcher: ebpfMatcher,
		ebpfEnabled: ebpfMatcher != nil && ebpfMatcher.IsEnabled(),
	}

	// 动态缓存模式：不预加载所有规则，只在运行时学习热点域名
	if dm.ebpfEnabled {
		errors.LogInfo(nil, "NewDomainMatcher: Dynamic caching enabled - ", len(domains), " domain rules will be learned on-demand")
		// 不预加载规则，让eBPF程序在运行时自动学习热点域名
	}

	return dm, nil
}

func (m *DomainMatcher) ApplyDomain(domain string) bool {
	domain = strings.ToLower(domain)
	errors.LogInfo(nil, "DomainMatcher.ApplyDomain: Matching domain ", domain, " (eBPF enabled: ", m.ebpfEnabled, ")")

	// eBPF快速路径
	if m.ebpfEnabled && m.ebpfMatcher != nil {
		errors.LogInfo(nil, "DomainMatcher: Trying eBPF match for ", domain)
		if matched, err := m.ebpfMatcher.MatchDomain(domain); err == nil {
			if matched {
				errors.LogInfo(nil, "DomainMatcher: eBPF GeoSite matched: ", domain)
				return true
			} else {
				errors.LogInfo(nil, "DomainMatcher: eBPF GeoSite no match for: ", domain)
			}
		} else {
			errors.LogInfo(nil, "DomainMatcher: eBPF GeoSite match error: ", err)
		}
	}

	// 标准匹配fallback
	result := len(m.matchers.Match(domain)) > 0
	if result {
		errors.LogInfo(nil, "DomainMatcher: Standard matcher matched: ", domain)
	} else {
		errors.LogInfo(nil, "DomainMatcher: No match for domain: ", domain)
	}
	return result
}

// Apply implements Condition.
func (m *DomainMatcher) Apply(ctx routing.Context) bool {
	domain := ctx.GetTargetDomain()
	if len(domain) == 0 {
		return false
	}
	return m.ApplyDomain(domain)
}

type MultiGeoIPMatcher struct {
	matchers []*GeoIPMatcher
	onSource bool
}

func NewMultiGeoIPMatcher(geoips []*GeoIP, onSource bool) (*MultiGeoIPMatcher, error) {
	var matchers []*GeoIPMatcher
	for _, geoip := range geoips {
		matcher, err := GlobalGeoIPContainer.Add(geoip)
		if err != nil {
			return nil, err
		}
		matchers = append(matchers, matcher)
	}

	matcher := &MultiGeoIPMatcher{
		matchers: matchers,
		onSource: onSource,
	}

	return matcher, nil
}

// Apply implements Condition.
func (m *MultiGeoIPMatcher) Apply(ctx routing.Context) bool {
	var ips []net.IP
	if m.onSource {
		ips = ctx.GetSourceIPs()
	} else {
		ips = ctx.GetTargetIPs()
	}
	for _, ip := range ips {
		for _, matcher := range m.matchers {
			if matcher.Match(ip) {
				return true
			}
		}
	}
	return false
}

type PortMatcher struct {
	port     net.MemoryPortList
	onSource bool
}

// NewPortMatcher create a new port matcher that can match source or destination port
func NewPortMatcher(list *net.PortList, onSource bool) *PortMatcher {
	return &PortMatcher{
		port:     net.PortListFromProto(list),
		onSource: onSource,
	}
}

// Apply implements Condition.
func (v *PortMatcher) Apply(ctx routing.Context) bool {
	if v.onSource {
		return v.port.Contains(ctx.GetSourcePort())
	} else {
		return v.port.Contains(ctx.GetTargetPort())
	}
}

type NetworkMatcher struct {
	list [8]bool
}

func NewNetworkMatcher(network []net.Network) NetworkMatcher {
	var matcher NetworkMatcher
	for _, n := range network {
		matcher.list[int(n)] = true
	}
	return matcher
}

// Apply implements Condition.
func (v NetworkMatcher) Apply(ctx routing.Context) bool {
	return v.list[int(ctx.GetNetwork())]
}

type UserMatcher struct {
	user    []string
	pattern []*regexp.Regexp
}

func NewUserMatcher(users []string) *UserMatcher {
	usersCopy := make([]string, 0, len(users))
	patternsCopy := make([]*regexp.Regexp, 0, len(users))
	for _, user := range users {
		if len(user) > 0 {
			if len(user) > 7 && strings.HasPrefix(user, "regexp:") {
				if re, err := regexp.Compile(user[7:]); err == nil {
					patternsCopy = append(patternsCopy, re)
				}
				// Items of users slice with an invalid regexp syntax are ignored.
				continue
			}
			usersCopy = append(usersCopy, user)
		}
	}
	return &UserMatcher{
		user:    usersCopy,
		pattern: patternsCopy,
	}
}

// Apply implements Condition.
func (v *UserMatcher) Apply(ctx routing.Context) bool {
	user := ctx.GetUser()
	if len(user) == 0 {
		return false
	}
	for _, u := range v.user {
		if u == user {
			return true
		}
	}
	for _, re := range v.pattern {
		if re.MatchString(user) {
			return true
		}
	}
	return false
}

type InboundTagMatcher struct {
	tags []string
}

func NewInboundTagMatcher(tags []string) *InboundTagMatcher {
	tagsCopy := make([]string, 0, len(tags))
	for _, tag := range tags {
		if len(tag) > 0 {
			tagsCopy = append(tagsCopy, tag)
		}
	}
	return &InboundTagMatcher{
		tags: tagsCopy,
	}
}

// Apply implements Condition.
func (v *InboundTagMatcher) Apply(ctx routing.Context) bool {
	tag := ctx.GetInboundTag()
	if len(tag) == 0 {
		return false
	}
	for _, t := range v.tags {
		if t == tag {
			return true
		}
	}
	return false
}

type ProtocolMatcher struct {
	protocols []string
}

func NewProtocolMatcher(protocols []string) *ProtocolMatcher {
	pCopy := make([]string, 0, len(protocols))

	for _, p := range protocols {
		if len(p) > 0 {
			pCopy = append(pCopy, p)
		}
	}

	return &ProtocolMatcher{
		protocols: pCopy,
	}
}

// Apply implements Condition.
func (m *ProtocolMatcher) Apply(ctx routing.Context) bool {
	protocol := ctx.GetProtocol()
	if len(protocol) == 0 {
		return false
	}
	for _, p := range m.protocols {
		if strings.HasPrefix(protocol, p) {
			return true
		}
	}
	return false
}

type AttributeMatcher struct {
	configuredKeys map[string]*regexp.Regexp
}

// Match implements attributes matching.
func (m *AttributeMatcher) Match(attrs map[string]string) bool {
	// header keys are case insensitive most likely. So we do a convert
	httpHeaders := make(map[string]string)
	for key, value := range attrs {
		httpHeaders[strings.ToLower(key)] = value
	}
	for key, regex := range m.configuredKeys {
		if a, ok := httpHeaders[key]; !ok || !regex.MatchString(a) {
			return false
		}
	}
	return true
}

// Apply implements Condition.
func (m *AttributeMatcher) Apply(ctx routing.Context) bool {
	attributes := ctx.GetAttributes()
	if attributes == nil {
		return false
	}
	return m.Match(attributes)
}
