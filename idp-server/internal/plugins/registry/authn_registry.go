package registry

import pluginport "idp-server/internal/ports/plugin"

// AuthnRegistry 是认证方式插件的查找表。
// 应用层只关心“按 method type 找到实现”，不需要知道具体是密码、联邦 OIDC 还是别的方式。
type AuthnRegistry struct {
	methods map[pluginport.AuthnMethodType]pluginport.AuthnMethod
}

func NewAuthnRegistry(methods ...pluginport.AuthnMethod) *AuthnRegistry {
	// 注册表在启动阶段一次性装入默认插件；
	// nil 插件会被忽略，方便按配置条件启用/禁用某些认证方式。
	registry := &AuthnRegistry{
		methods: make(map[pluginport.AuthnMethodType]pluginport.AuthnMethod, len(methods)),
	}

	for _, method := range methods {
		if method == nil {
			continue
		}
		registry.methods[method.Type()] = method
	}

	return registry
}

func (r *AuthnRegistry) Register(method pluginport.AuthnMethod) {
	// Register 允许后续测试或扩展模块动态追加实现。
	if r.methods == nil {
		r.methods = make(map[pluginport.AuthnMethodType]pluginport.AuthnMethod)
	}
	if method == nil {
		return
	}
	r.methods[method.Type()] = method
}

func (r *AuthnRegistry) Get(methodType pluginport.AuthnMethodType) (pluginport.AuthnMethod, bool) {
	// 缺失返回 (nil, false)，由上层统一映射成“不支持的认证方式”。
	method, ok := r.methods[methodType]
	return method, ok
}
