package ch.bytecrowd.jwt.rest;

import ch.bytecrowd.jwt.domain.User;
import io.quarkus.hibernate.reactive.panache.common.runtime.ReactiveTransactional;
import io.quarkus.panache.common.Parameters;
import io.smallrye.mutiny.Uni;
import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.eclipse.microprofile.jwt.JsonWebToken;

import javax.annotation.security.PermitAll;
import javax.annotation.security.RolesAllowed;
import javax.inject.Inject;
import javax.ws.rs.*;
import javax.ws.rs.core.Response;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.List;
import java.util.Map;
import java.util.Set;

@Path("/api/users")
public class UserResource {

    public static final String ROLE_ADMIN = "ADMIN";
    public static final String ROLE_USER = "USER";
    public static final Set ALL_ROLES = Set.of(ROLE_ADMIN, ROLE_USER);

    private final String issuer;
    private final  int maxAge;
    private final JsonWebToken jwt;

    @Inject
    public UserResource(
            @ConfigProperty(name = "mp.jwt.verify.issuer")String issuer,
            @ConfigProperty(name = "ch.bytecrowd.quarkusjwt.jwt.duration") int maxAge,
            JsonWebToken jwt
    ) {
        this.issuer = issuer;
        this.maxAge = maxAge;
        this.jwt = jwt;
    }

    @GET
    @PermitAll
    public Uni<Response> findAll() {
        return User.findAll().list().map(users ->
                Response.ok(users).build()
        );
    }

    @POST
    @ReactiveTransactional
    @RolesAllowed({AuthenticationResource.ROLE_ADMIN})
    public Uni<Response> create(User user, @QueryParam("password") String password) {
        return Uni.createFrom().item(password)
                .map(UserResource::sha512)
                .map(hash -> user.uuid(null).password(hash))
                .flatMap(u -> u.persist())
                .map(u -> Response.created(URI.create("/api/user/"))
                        .entity(u)
                        .build()
                );
    }

    @PUT
    @ReactiveTransactional
    @RolesAllowed({AuthenticationResource.ROLE_USER})
    public Uni<Response> updatePassword(@QueryParam("password") String password) {
        Uni<User> user = Uni.createFrom().item(jwt.getName())
                .flatMap(login -> User.find(
                        "from User u where u.login = :login",
                        Map.of("login", login)
                ).firstResult());

        return user.invoke(u -> {
                    String hash = sha512(password);
                    u.password(hash);
                }).flatMap(u -> u.persist())
                .map(u -> Response.ok(u).build());
    }

    @PUT
    @ReactiveTransactional
    @Path("/roles")
    @RolesAllowed({AuthenticationResource.ROLE_ADMIN})
    public Uni<Response> updateRole(@QueryParam("login") String login, @QueryParam("roles") Set<String> roles) {
        Uni<User> user = User.find(
                "from User u where u.login = :login",
                Map.of("login", login)
        ).firstResult();

        return user
                .invoke(u -> u.setRoles(roles))
                .flatMap(u -> u.persist())
                .map(u -> Response.ok(u).build());
    }

    public static String sha512(String message) {
        try {
            MessageDigest sha512 = MessageDigest.getInstance("SHA512");
            byte[] digest = sha512.digest(message.getBytes(StandardCharsets.UTF_8));
            final StringBuilder hash = new StringBuilder();
            for (int i = 0; i < digest.length; i++) {
                hash.append(
                        String.format("%02x", digest[i])
                );
            }
            return hash.toString();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }
}
