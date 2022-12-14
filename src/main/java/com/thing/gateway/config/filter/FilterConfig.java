package com.thing.gateway.config.filter;

import lombok.RequiredArgsConstructor;
import org.springframework.cloud.gateway.route.RouteLocator;
import org.springframework.cloud.gateway.route.builder.RouteLocatorBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
@RequiredArgsConstructor
public class FilterConfig {

    private final AuthenticationFilter filter;

    @Bean
    public RouteLocator routes(RouteLocatorBuilder builder) {
        return builder.routes()
                .route("auth-service", r -> r.path("/auth/**")
                        .filters(f -> f.filter(filter))
                        .uri("lb://AUTH-SERVICE"))
                .route("user-service", r -> r.path("/clients/**")
                        .filters(f -> f.filter(filter))
                        .uri("lb://CLIENT-SERVICE"))
                .route("item-service", r -> r.path("/items/**")
                        .filters(f -> f.filter(filter))
                        .uri("lb://ITEM-SERVICE"))
                .route("contract-service", r -> r.path("/contracts/**")
                        .filters(f -> f.filter(filter))
                        .uri("lb://CONTRACT-SERVICE"))
                .route("basket-service", r -> r.path("/baskets/**")
                        .filters(f -> f.filter(filter))
                        .uri("lb://BASKET-SERVICE"))
                .build();
    }

}
