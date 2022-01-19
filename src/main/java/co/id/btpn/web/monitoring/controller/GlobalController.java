package co.id.btpn.web.monitoring.controller;

import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ModelAttribute;

import co.id.btpn.web.monitoring.security.CustomLdapUserDetails;


@ControllerAdvice
public class GlobalController {

 

    private static final Logger LOG = LoggerFactory.getLogger(GlobalController.class);


    @ModelAttribute   // A Model Attribute Adder method
    public void setGlobalModelAttributes(HttpServletRequest request, HttpServletResponse resp, Model model) throws java.io.IOException , javax.naming.InvalidNameException{
      //blank

      try{
            HttpSession session = request.getSession();

            Object principal = SecurityContextHolder.getContext().getAuthentication().getPrincipal();
            String dn = "";
            if (principal instanceof CustomLdapUserDetails) {
                dn = ((CustomLdapUserDetails) principal).getDn();
            }

            LdapName dnObj = new LdapName(dn);

            Boolean found = false;
            for (Rdn rdn : dnObj.getRdns()) {
                if (rdn.getType().equalsIgnoreCase("CN")) {
                    session.setAttribute("userName", rdn.getValue());
                    found = true;
                    break;
                }
            }
            if (Boolean.FALSE.equals(found)) {
                if (principal instanceof org.springframework.security.core.userdetails.User) {
                    session.setAttribute("userName",
                            ((org.springframework.security.core.userdetails.User) principal).getUsername());
                } else if (principal instanceof CustomLdapUserDetails) {
                    session.setAttribute("userName", ((CustomLdapUserDetails) principal).getUsername());
                }
            }

            if (principal instanceof CustomLdapUserDetails) {
                session.setAttribute("userMail", ((CustomLdapUserDetails) principal).getMail());
                try{
                    if(((CustomLdapUserDetails) principal).getThumbnailPhoto() !=null){
                        session.setAttribute("userThumbnailPhoto", ((CustomLdapUserDetails) principal).getThumbnailPhoto().replaceAll("[\\n\\t\\r ]", ""));
                    }else{
                        LOG.info(">>>>> userThumbnailPhoto NOT FOUND");
                    }
                }catch(Exception ex){
                    LOG.info(">>>>> userThumbnailPhoto NOT FOUND");
                }
            }
        }catch(java.lang.NullPointerException ex){
            LOG.info(">>>>> Exception "+ ex.getMessage());
        }

    }
}




