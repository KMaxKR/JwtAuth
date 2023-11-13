package ks.msx.jwt.entity;

import lombok.Getter;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;

@RequiredArgsConstructor
public enum Role {
    USER(Set.of(Permissions.READ)),
    ADMIN(Set.of(Permissions.READ, Permissions.WRITE)),
    ROOT(Set.of(Permissions.READ, Permissions.WRITE, Permissions.PUT, Permissions.DELETE));

    @Getter
    private final Set<Permissions> permissionsSet;

    public List<SimpleGrantedAuthority> authorities(){
        var authorities = new ArrayList<>(getPermissionsSet()
                .stream()
                .map(permissions -> new SimpleGrantedAuthority(permissions.name()))
                .toList()
        );
        authorities.add(new SimpleGrantedAuthority("ROLE_" + this.name()));
        return authorities;
    }
}
