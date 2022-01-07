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

    @Override
    public boolean isEnabled() {
        return details.isEnabled() && getUsername().equals(env.getRequiredProperty("ldap.username"));
    }

    @Override
    public String getDn() {
        return details.getDn();
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return details.getAuthorities();
    }

    @Override
    public String getPassword() {
        return details.getPassword();
    }
    
    @Override
    public String getUsername() {
        return details.getUsername();
    }
    
    @Override
    public boolean isAccountNonExpired() {
        return details.isAccountNonExpired();
    }
    
    @Override
    public boolean isAccountNonLocked() {
        return details.isAccountNonLocked();
    }
    
    @Override
    public boolean isCredentialsNonExpired() {
        return details.isCredentialsNonExpired();
    }

    @Override
    public void eraseCredentials() {
        details.eraseCredentials();
        
    }

    public String getCn() {
        return cn;
    }

    public void setCn(String cn) {
        this.cn = cn;
    }

    public LdapUserDetails getDetails() {
        return details;
    }

    public void setDetails(LdapUserDetails details) {
        this.details = details;
    }

    public Environment getEnv() {
        return env;
    }

    public void setEnv(Environment env) {
        this.env = env;
    }
}
