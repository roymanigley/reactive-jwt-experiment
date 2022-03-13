package ch.bytecrowd.helpers;

import io.smallrye.jwt.build.Jwt;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

public class TokenGenerator {

    public static void main(String[] args) {
        String token = generateToken(
                "",
                new HashSet<>(Arrays.asList("User", "Admin")),
                "https://bytecrowd.ch/issuer"
        );
        System.out.println(
                "curl -H \"Authorization: Bearer " + token + "\" \\\n" +
                        "http://localhost:8080/api/secured/check"
        );
    }

    public static String generateToken(
            String login,
            Set<String> roles,
            String issuer
    ) {
        return Jwt.issuer(issuer)
                        .upn(login)
                        .groups(roles)
                        .sign();
    }
}