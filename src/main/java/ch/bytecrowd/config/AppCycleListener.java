package ch.bytecrowd.config;

import ch.bytecrowd.jwt.domain.User;
import ch.bytecrowd.jwt.rest.UserResource;
import io.quarkus.hibernate.reactive.panache.common.runtime.ReactiveTransactional;
import io.quarkus.runtime.StartupEvent;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.enterprise.context.ApplicationScoped;
import javax.enterprise.event.Observes;

@ApplicationScoped
public class AppCycleListener {

    private static final Logger LOG = LoggerFactory.getLogger(AppCycleListener.class);

    @ReactiveTransactional
    void onStart(@Observes StartupEvent event) {
        new User()
                .login("admin")
                .password(UserResource.sha512("admin"))
                .roles(UserResource.ALL_ROLES)
                .persist()
                .invoke(user -> LOG.info("Initial user created: {}", user))
                .subscribe().with(e -> {});
    }
}
