package com.example.demo.formAuth;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;

@Configuration
@EnableWebSecurity
public class SecSecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    PasswordEncoder passwordEncoder;

    @Override
    protected void configure(final AuthenticationManagerBuilder auth) throws Exception {
        auth.inMemoryAuthentication()
                .passwordEncoder(passwordEncoder)
                .withUser("user1").password(passwordEncoder.encode("user1Pass")).roles("USER")
                .and()
                .withUser("user2").password(passwordEncoder.encode("user2Pass")).roles("USER", "ADMIN")
                .and()
                .withUser("admin").password(passwordEncoder.encode("adminPass")).roles("ADMIN");
}

    @Override
    protected void configure(HttpSecurity http) throws Exception {
     http.csrf().disable()
             .authorizeRequests()
             .antMatchers("/admin/**").hasRole("ADMIN")
             .antMatchers("/anonymous*").anonymous()
             .antMatchers("/login").permitAll()
             .anyRequest().authenticated()
             .and()
             .formLogin()
             .loginPage("/login")
//             .loginProcessingUrl("/login")
             .defaultSuccessUrl("/homepage", true)
             .failureUrl("/login?error=true")
//             .failureHandler(authenticationFailureHandler())
             .permitAll()
             .and()
             .logout()
             .logoutUrl("/perform_logout")
             .logoutSuccessUrl("/login?logout=true")
             .deleteCookies("JSESSIONID")
             .permitAll()
             .logoutSuccessHandler(logoutSuccessHandler());
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public AuthenticationFailureHandler authenticationFailureHandler() {
        return new CustomAuthenticationFailureHandler();
    }

    @Bean
    public LogoutSuccessHandler logoutSuccessHandler(){
        return new CustomLogoutSuccessHandler();
    }
}
