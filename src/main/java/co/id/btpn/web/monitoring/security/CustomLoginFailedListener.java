package co.id.btpn.web.monitoring.security;


import java.io.IOException;
import java.util.Date;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.stereotype.Component;

@Component
public class CustomLoginFailedListener implements AuthenticationFailureHandler {
  private RedirectStrategy redirectStrategy = new DefaultRedirectStrategy();
  
    private static final Logger LOG = LoggerFactory.getLogger(CustomLoginFailedListener.class);

    @Override
    public void onAuthenticationFailure(
      HttpServletRequest request,
      HttpServletResponse response,
      AuthenticationException exception) 
      throws IOException, ServletException {

          LOG.info(
            "Login Failed Timestamp --> {} exception --> {}  " ,  new Date().getTime() ,exception.getMessage());
            redirectStrategy.sendRedirect(request, response, "/login?error=true");    
    }
}
