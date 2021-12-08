package co.id.btpn.web.monitoring.util;

import javax.servlet.http.HttpSession;

import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import co.id.btpn.web.monitoring.security.CustomLdapUserDetails;

@Service
public class Util {

  
    
    public String getLoggedUserName(){
        Object principal = SecurityContextHolder.getContext().getAuthentication().getPrincipal();

        if (principal instanceof CustomLdapUserDetails) {
            return ((CustomLdapUserDetails) principal).getUsername();
        }else if (principal instanceof UserDetails) {
            return  ((UserDetails)principal).getUsername();
        }else {
            return principal.toString();
        }
    } 

    public String getLoggedCN() throws  javax.naming.InvalidNameException{
        Object principal = SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        String dn = "",cn = "";
        if (principal instanceof CustomLdapUserDetails) {
            dn = ((CustomLdapUserDetails) principal).getDn();
        }

        LdapName dnObj = new LdapName(dn);

        for (Rdn rdn : dnObj.getRdns()) {
            if (rdn.getType().equalsIgnoreCase("CN")) {
                cn = (String) rdn.getValue();
                break;
            }
        }
        return cn;
    } 

    public boolean isUserLoggedIn() {
        if (getLoggedUserName().equalsIgnoreCase("anonymousUser")) {
            return false;
        }else{
            return true;
        }
    }
}
