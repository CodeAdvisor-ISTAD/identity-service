package co.istad.identityservice.config;
//
//import org.springframework.context.annotation.Configuration;
//import org.springframework.web.servlet.config.annotation.CorsRegistry;
//import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;
//
//@Configuration
//public class CorsConfig implements WebMvcConfigurer {
//
//    @Override
//    public void addCorsMappings(CorsRegistry registry) {
//        registry.addMapping("/**")
//                .allowedOrigins(
//                        "*"
//                )
//                .allowedMethods("GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH")
//                .allowedHeaders("*");
////                .allowCredentials(true)
////                .maxAge(3600);
//    }
//
//
//}


import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Configuration
public class CoreConfig implements WebMvcConfigurer {

    @Override
    public void addCorsMappings(CorsRegistry registry) {
        registry.addMapping("/**")
//                .allowedOrigins("http://localhost:8001","http://localhost:3000","http://localhost:8000","http://localhost:9090","null")
//                .allowedOrigins("https://khotixs-auth.devkh.asia","https://khotixs.devkh.asia","")
//                .allowedOrigins("https://khotixs-auth.devkh.asia","https://khotixs.devkh.asia","https://oauth.khotixs.istad.co")
                .allowedOrigins("*")
                .allowedMethods("GET", "POST", "PUT", "DELETE","PATCH", "OPTIONS")
                .allowedHeaders("*");
//                .allowCredentials(true);
    }
}
