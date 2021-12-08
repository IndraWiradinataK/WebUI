package co.id.btpn.web.monitoring.security;


import java.util.Collection;

import org.springframework.core.env.Environment;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.ldap.userdetails.LdapUserDetails;


public class CustomLdapUserDetails implements LdapUserDetails {
    private static final long serialVersionUID = 1L;
    
    private LdapUserDetails details;
    private Environment env;
    private String thumbnailPhoto;
    private String mail;
    private String cn;
    
    public CustomLdapUserDetails(LdapUserDetails details, Environment env) {
        this.details = details;
        this.env = env;
    }

    public String getMail() {
        return this.mail;
    }

    public String getThumbnailPhoto() {
        return this.thumbnailPhoto; 
    }

    public void setMail(String mail) {
        this.mail=mail;
    }

    public void setThumbnailPhoto(String thumbnailPhoto) {
        this.thumbnailPhoto = thumbnailPhoto;
    }

    
    public boolean isEnabled() {
        return details.isEnabled() && getUsername().equals(env.getRequiredProperty("ldap.username"));
    }
    
    public String getDn() {
        return details.getDn();
    }
    
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return details.getAuthorities();
    }
    
    public String getPassword() {
        return details.getPassword();
    }
    
    public String getUsername() {
        return details.getUsername();
    }
    
    public boolean isAccountNonExpired() {
        return details.isAccountNonExpired();
    }
    
    public boolean isAccountNonLocked() {
        return details.isAccountNonLocked();
    }
    
    public boolean isCredentialsNonExpired() {
        return details.isCredentialsNonExpired();
    }

    @Override
    public void eraseCredentials() {
        // TODO Auto-generated method stub
        details.eraseCredentials();
        
    }

    public String getCn() {
        return cn;
    }

    public void setCn(String cn) {
        this.cn = cn;
    }
}
