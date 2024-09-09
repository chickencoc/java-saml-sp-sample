package saml.sample.sp;

import lombok.Getter;
import lombok.Setter;
import lombok.ToString;
import org.opensaml.saml2.core.Attribute;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

@Getter
@Setter
@ToString
final class SamlUserDetails implements UserDetails {

    private String username;
    private String email;
    private String federationIdentifier;
    private String personname;
    private List<GrantedAuthority> authorities = new ArrayList<>();

    public SamlUserDetails(List<Attribute> samlAttributes) {
        for (Attribute attr : samlAttributes) {
            String attrName  = attr.getName();
            switch (attrName) {
                case "idpuserid" :
                    username = SamlUtil.getStringFromXMLObject(attr.getAttributeValues().get(0));
                    break;
                case "idpuseremail":
                    email = SamlUtil.getStringFromXMLObject(attr.getAttributeValues().get(0));
                    break;
                case "idpusernm":
                    personname = SamlUtil.getStringFromXMLObject(attr.getAttributeValues().get(0));
                    break;
            }
        }
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return authorities;
    }

    @Override
    public String getPassword() {
        return null;
    }

    @Override
    public String getUsername() {
        return username;
    }

    @Override
    public boolean isAccountNonExpired() {
        return false;
    }

    @Override
    public boolean isAccountNonLocked() {
        return false;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return false;
    }

    @Override
    public boolean isEnabled() {
        return false;
    }
}