package registry

import pluginport "idp-server/internal/ports/plugin"

// GrantRegistry 是 OAuth2 grant type 到具体处理器的映射表。
// Token endpoint 先做客户端认证，再通过这里把请求分发给对应 grant handler。
type GrantRegistry struct {
	handlers map[pluginport.GrantHandlerType]pluginport.GrantHandler
}

func NewGrantRegistry(handlers ...pluginport.GrantHandler) *GrantRegistry {
	// 启动阶段集中注册支持的 grant type，形成一个稳定的分发表。
	registry := &GrantRegistry{
		handlers: make(map[pluginport.GrantHandlerType]pluginport.GrantHandler, len(handlers)),
	}

	for _, handler := range handlers {
		if handler == nil {
			continue
		}
		registry.handlers[handler.Type()] = handler
	}

	return registry
}

func (r *GrantRegistry) Register(handler pluginport.GrantHandler) {
	// 后注册会覆盖同类型旧实现，便于测试替身或定制插件替换默认行为。
	if r.handlers == nil {
		r.handlers = make(map[pluginport.GrantHandlerType]pluginport.GrantHandler)
	}
	if handler == nil {
		return
	}
	r.handlers[handler.Type()] = handler
}

func (r *GrantRegistry) Get(handlerType pluginport.GrantHandlerType) (pluginport.GrantHandler, bool) {
	// 这里不做兜底；是否支持某个 grant type 由调用方显式判断。
	handler, ok := r.handlers[handlerType]
	return handler, ok
}
