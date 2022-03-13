package ch.bytecrowd.jwt.domain;

import com.fasterxml.jackson.annotation.JsonIgnore;
import io.quarkus.hibernate.reactive.panache.PanacheEntityBase;

import javax.persistence.*;
import java.util.Set;
import java.util.UUID;

@Entity
@Table(name = "jwt_user")
public class User extends PanacheEntityBase {

    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    private UUID uuid;
    @Column(name = "login")
    private String login;
    @JsonIgnore
    @Column(name = "password")
    private String password;
    @ElementCollection(fetch = FetchType.EAGER)
    private Set<String> roles;

    public UUID getUuid() {
        return uuid;
    }

    public void setUuid(UUID uuid) {
        this.uuid = uuid;
    }

    public User uuid(UUID uuid) {
        setUuid(uuid);
        return this;
    }

    public String getLogin() {
        return login;
    }

    public void setLogin(String login) {
        this.login = login;
    }

    public User login(String login) {
        this.setLogin(login);
        return this;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public User password(String password) {
        this.setPassword(password);
        return this;
    }

    public Set<String> getRoles() {
        return roles;
    }

    public void setRoles(Set<String> roles) {
        this.roles = roles;
    }

    public User roles(Set<String> roles) {
        this.setRoles(roles);
        return this;
    }

    @Override
    public String toString() {
        return "User{" +
                "uuid=" + uuid +
                ", login='" + login + '\'' +
                ", password='" + password + '\'' +
                ", roles=" + roles +
                '}';
    }
}
