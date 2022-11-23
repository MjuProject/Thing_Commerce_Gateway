package com.thing.gateway.config.filter;

import com.thing.gateway.config.jwt.JwtTokenUtils;
import lombok.RequiredArgsConstructor;
import org.springframework.cloud.context.config.annotation.RefreshScope;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.Map;

@RefreshScope // 설정 변경시 서버를 재실행
@Component
@RequiredArgsConstructor
public class AuthenticationFilter implements GatewayFilter {

    private final JwtTokenUtils jwtTokenUtils;
    private final String TOKEN_PREFIX = "Bearer ";

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        ServerHttpRequest request = exchange.getRequest();

        if(request.getHeaders().containsKey("Authorization")){
            String token = getAuthHeaderValue(request);

            if (StringUtils.hasText(token) && jwtTokenUtils.validateToken(token)){
                this.addRequestUserInfoHeader(exchange, token);
            }
        }

        return chain.filter(exchange);
    }

    private String getAuthHeaderValue(ServerHttpRequest request) {
        String bearerToken = request.getHeaders().getOrEmpty("Authorization").get(0);
        if (StringUtils.hasText(bearerToken) && bearerToken.startsWith(TOKEN_PREFIX)) {
            return bearerToken.substring(TOKEN_PREFIX.length());
        }
        return null;
    }

    private void addRequestUserInfoHeader(ServerWebExchange exchange, String token){
        Map<String, String> userInfo = jwtTokenUtils.getUserInfo(token);
        exchange.getRequest().mutate()
                .header("clientIdx", userInfo.get("clientIdx"))
                .header("role", userInfo.get("role"))
                .build();
    }

}
