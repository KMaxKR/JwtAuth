package ks.msx.jwt.entity;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
public enum Permissions {
    WRITE("WRITE"),
    READ("READ"),
    PUT("PUT"),
    DELETE("DELETE");

    @Getter
    public final String permissions;
}
