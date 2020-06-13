package com.lyp.learn.config;

import com.lyp.learn.config.auth.MyAuthenticationFailureHandler;
import com.lyp.learn.config.auth.MyAuthenticationSuccessHandler;
import com.lyp.learn.config.auth.MyExpiredSessionStrategy;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import javax.annotation.Resource;

@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Resource
    private MyAuthenticationSuccessHandler myAuthenticationSuccessHandler;

    @Resource
    private MyAuthenticationFailureHandler myAuthenticationFailureHandler;

    /**
     * spring security 总体配置
     * @param http
     * @throws Exception
     */
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.csrf().disable() //禁用跨站csrf攻击防御，后面的章节会专门讲解
                .formLogin()
                .loginPage("/login.html")//用户未登录时，访问任何资源都转跳到该路径，即登录页面
                .loginProcessingUrl("/login")//登录表单form中action的地址，也就是处理认证请求的路径
//                .usernameParameter("uname") //登录表单的账号参数，不修改的话默认是username (login.html)
//                .passwordParameter("pword") //登录表单中密码参数，不修改的话默认是password (login.html)
//                .successHandler(myAuthenticationSuccessHandler)
//                .failureHandler(myAuthenticationFailureHandler)
                /** 不要配置defaultSuccessUrl和failureUrl，否则自定义handler将失效。handler配置与URL配置只能二选一*/
                .defaultSuccessUrl("/index")//登录认证成功后默认转跳的路径
                .failureUrl("/login.html") //登录认证是被跳转页面
                .and()
                .authorizeRequests() //权限控制
                .antMatchers("/login.html", "/login")
                    .permitAll()//不需要通过登录验证就可以被访问的资源路径
                .antMatchers("/biz1", "/biz2") //需要对外暴露的资源路径
                    .hasAnyAuthority("ROLE_user", "ROLE_admin")  //user角色和admin角色都可以访问
                .antMatchers("/syslog", "/sysuser")
                    .hasAnyRole("admin")  //admin角色可以访问
                //.antMatchers("/syslog").hasAuthority("sys:log") //  hasAuthority 设置和 url 一一对应 资源的唯一标识
                //.antMatchers("/sysuser").hasAuthority("sys:user")
                .anyRequest().authenticated()

        .and()
            .sessionManagement()
                // 无状态session ,就是不用session ，可以分布式部署
//        .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
        .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED)
                // 设置 session 的过期时间，过期之后跳转的页面
        .invalidSessionUrl("/login.html")

                // 迁移session
        .sessionFixation().migrateSession()
                // 重新创建session
//        .sessionFixation().newSession()

            // 限制同一个用户，只能同时登陆一个账号
        .maximumSessions(1)
                // 登陆之后，允许再次登录，但是会让上次登录下下线
        .maxSessionsPreventsLogin(false)

        .expiredSessionStrategy(new MyExpiredSessionStrategy())
        ;
    }

    /**
     * 用户配置
     * @param auth
     * @throws Exception
     */
    @Override
    public void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.inMemoryAuthentication()
                .withUser("user")
                .password(passwordEncoder().encode("123456"))
                .roles("user")
            .and()
                .withUser("admin")
                .password(passwordEncoder().encode("123456"))
                //.authorities("sys:log","sys:user")
                .roles("admin")
            .and()
                .passwordEncoder(passwordEncoder());//配置BCrypt加密
    }

    /**
     * 密码编码器
     * @return
     */
    @Bean
    public PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }

    /**
     * 静态资源访问
     * @param web
     */
    @Override
    public void configure(WebSecurity web) {
        //将项目中静态资源路径开放出来
        web.ignoring().antMatchers( "/css/**", "/fonts/**", "/img/**", "/js/**");
    }
}
