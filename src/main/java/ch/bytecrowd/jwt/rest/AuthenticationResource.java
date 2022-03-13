package ch.bytecrowd.jwt.rest;

import ch.bytecrowd.helpers.TokenGenerator;
import ch.bytecrowd.jwt.domain.User;
import io.quarkus.security.Authenticated;
import io.smallrye.mutiny.Uni;
import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.eclipse.microprofile.jwt.JsonWebToken;

import javax.inject.Inject;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.QueryParam;
import javax.ws.rs.core.NewCookie;
import javax.ws.rs.core.Response;
import java.nio.file.AccessDeniedException;
import java.util.Map;
import java.util.Set;

@Path("/api/auth")
public class AuthenticationResource {

    public static final String ROLE_ADMIN = "ADMIN";
    public static final String ROLE_USER = "USER";
    public static final Set ALL_ROLES = Set.of(ROLE_ADMIN, ROLE_USER);

    private final String issuer;
    private final  int maxAge;
    private final JsonWebToken jwt;

    @Inject
    public AuthenticationResource(
            @ConfigProperty(name = "mp.jwt.verify.issuer")String issuer,
            @ConfigProperty(name = "ch.bytecrowd.quarkusjwt.jwt.duration") int maxAge,
            JsonWebToken jwt
    ) {
        this.issuer = issuer;
        this.maxAge = maxAge;
        this.jwt = jwt;
    }

    @POST
    public Uni<Response> login(@QueryParam("login") String login, @QueryParam("password") String password) {
        String hash = UserResource.sha512(password);
        Uni<User> user = User.find(
                "select u from User u where u.login = :login and u.password = :pass",
                        Map.of("login", login, "pass", hash))
                .firstResult();

        return user
                .onItem().ifNull().failWith(new AccessDeniedException("login failed for: " + login))
                .map(u -> TokenGenerator.generateToken(u.getLogin(), u.getRoles(), issuer))
                .map(token -> getOkResponse(token, maxAge))
                .onItem().ifNull().continueWith(() -> getUnauthorizedResponse());
    }

    @POST
    @Path("/:refresh")
    @Authenticated
    public Uni<Response> refresh() {
        return Uni.createFrom().item(jwt.getName())
                .map(login -> TokenGenerator.generateToken(login, ALL_ROLES, issuer))
                .map(token -> getOkResponse(token, maxAge));
    }

    @GET
    @Path("/:logout")
    public Uni<Response> logout() {
        return Uni.createFrom().item(0)
                .map(maxAge -> getOkResponse(null, maxAge));
    }

    private Response getOkResponse(String token, Integer maxAge) {
        return Response.status(Response.Status.OK).cookie(getNewCookie(token, maxAge)).build();
    }

    private Response getUnauthorizedResponse() {
        return Response.status(Response.Status.UNAUTHORIZED).cookie(getNewCookie(null, 0)).build();
    }

    private NewCookie getNewCookie(String token, int maxAge) {
        return new NewCookie("jwt", token, "/", "localhost", "", maxAge, false, true);
    }
}
