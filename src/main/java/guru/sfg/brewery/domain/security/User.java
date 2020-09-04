package guru.sfg.brewery.domain.security;

import guru.sfg.brewery.domain.Customer;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.Singular;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import org.springframework.security.core.CredentialsContainer;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import javax.persistence.CascadeType;
import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.FetchType;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.JoinColumn;
import javax.persistence.JoinTable;
import javax.persistence.ManyToMany;
import javax.persistence.ManyToOne;
import javax.persistence.Transient;
import java.sql.Timestamp;
import java.util.Collection;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Entity
public class User implements UserDetails, CredentialsContainer {

    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    private Integer id;

    private String username;
    private String password;

    @Builder.Default
    private Boolean useGoogle2fa = false;

    private String google2faSecret;

    @Transient
    private Boolean google2faRequired = true;

    @Singular
    @ManyToMany(cascade = {CascadeType.MERGE}, fetch = FetchType.EAGER)
    @JoinTable(name = "user_role",
            joinColumns = {@JoinColumn(name = "USER_ID", referencedColumnName = "ID")},
            inverseJoinColumns = {@JoinColumn(name = "ROLE_ID", referencedColumnName = "ID")})
    private Set<Role> roles;

    @Transient
    private Set<Authority> authorities;

    @ManyToOne(fetch = FetchType.EAGER)
    private Customer customer;

    @Builder.Default
    private Boolean accountNonExpired = true;

    @Builder.Default
    private Boolean accountNonLocked = true;

    @Builder.Default
    private Boolean credentialsNonExpired = true;

    @Builder.Default
    private Boolean enabled = true;

    public @NotNull Set<GrantedAuthority> getAuthorities() {
        return roles.stream()
                .map(Role::getAuthorities)
                .flatMap(Collection::stream)
                .map(Authority::getPermission)
                .map(SimpleGrantedAuthority::new)
                .collect(Collectors.toSet());
    }

    @Override
    public boolean isAccountNonExpired() {
        return accountNonExpired;
    }

    @Override
    public boolean isAccountNonLocked() {
        return accountNonLocked;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return credentialsNonExpired;
    }

    @Override
    public boolean isEnabled() {
        return enabled;
    }

    @Override
    public void eraseCredentials() {
        password = null;
    }

    @CreationTimestamp
    @Column(updatable = false)
    private Timestamp createdDate;

    @UpdateTimestamp
    private Timestamp lastModifiedDate;

    public void setCreatedDate(@Nullable Timestamp createdDate) {
        this.createdDate = Optional.ofNullable(createdDate)
                .map(Timestamp::clone)
                .map(Timestamp.class::cast)
                .orElse(null);
    }

    public @Nullable Timestamp getCreatedDate() {
        return Optional.ofNullable(createdDate)
                .map(Timestamp::clone)
                .map(Timestamp.class::cast)
                .orElse(null);
    }

    public void setLastModifiedDate(@Nullable Timestamp lastModifiedDate) {
        this.lastModifiedDate = Optional.ofNullable(lastModifiedDate)
                .map(Timestamp::clone)
                .map(Timestamp.class::cast)
                .orElse(null);
    }

    public @Nullable Timestamp getLastModifiedDate() {
        return Optional.ofNullable(lastModifiedDate)
                .map(Timestamp::clone)
                .map(Timestamp.class::cast)
                .orElse(null);
    }
}
