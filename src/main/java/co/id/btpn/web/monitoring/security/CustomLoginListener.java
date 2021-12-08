package co.id.btpn.web.monitoring.security;


import java.io.IOException;
import java.util.Date;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

@Component
public class CustomLoginListener implements AuthenticationSuccessHandler {

    private static final Logger LOG = LoggerFactory.getLogger(CustomLoginListener.class);
    private RedirectStrategy redirectStrategy = new DefaultRedirectStrategy();
  
    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
    Authentication authentication) throws IOException {
        UserDetails ud = (UserDetails) authentication.getPrincipal();
        LOG.info(
            "Login Timestamp --> {} User --> {}" ,  new Date().getTime() ,ud.getUsername() );

            redirectStrategy.sendRedirect(request, response, "/dashboard"); 

    }
}
