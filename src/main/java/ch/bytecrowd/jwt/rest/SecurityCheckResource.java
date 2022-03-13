package ch.bytecrowd.jwt.rest;


import io.quarkus.security.Authenticated;
import org.eclipse.microprofile.jwt.JsonWebToken;

import javax.annotation.security.PermitAll;
import javax.annotation.security.RolesAllowed;
import javax.inject.Inject;
import javax.ws.rs.GET;
import javax.ws.rs.InternalServerErrorException;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.SecurityContext;
import java.util.stream.Collectors;

@Path("/api/security-check")
public class SecurityCheckResource {

    private final JsonWebToken jwt;

    @Inject
    public SecurityCheckResource(JsonWebToken jwt) {
        this.jwt = jwt;
    }

    @GET()
    @Path("/permit-all")
    @PermitAll
    @Produces(MediaType.TEXT_PLAIN)
    public String checkPermitAll(@Context SecurityContext ctx) {
        return getResponseString(ctx);
    }

    @GET()
    @Path("/authenticated")
    @Authenticated
    @Produces(MediaType.TEXT_PLAIN)
    public String checkAuthorized(@Context SecurityContext ctx) {
        return getResponseString(ctx);
    }

    @GET
    @Path("(roles-allowed")
    @RolesAllowed({AuthenticationResource.ROLE_USER, AuthenticationResource.ROLE_ADMIN})
    @Produces(MediaType.TEXT_PLAIN)
    public String checkRolesAllowed(@Context SecurityContext ctx) {
        return getResponseString(ctx) + ",\nbirthdate: " + jwt.getClaim("birthdate");
    }

    private String getResponseString(SecurityContext ctx) {
        String name;
        if (ctx.getUserPrincipal() == null) {
            name = "anonymous";
        } else if (!ctx.getUserPrincipal().getName().equals(jwt.getName())) {
            throw new InternalServerErrorException("Principal and JsonWebToken names do not match");
        } else {
            name = ctx.getUserPrincipal().getName();
        }
        return String.format("name: %s,\n"
                        + "isHttps: %s,\n"
                        + "roles: [%s],\n"
                        + "authScheme: %s,\n"
                        + "hasJWT: %s",
                name, ctx.isSecure(), jwt.getGroups().stream().collect(Collectors.joining(",")),ctx.getAuthenticationScheme(), hasJwt());
    }

    private boolean hasJwt() {
        return jwt.getClaimNames() != null;
    }
}
