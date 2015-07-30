package sales.users.domain;

import com.fasterxml.jackson.annotation.JsonAutoDetect;
import com.fasterxml.jackson.annotation.JsonProperty;
import sales.roles.domain.Role;

import javax.persistence.*;
import java.io.Serializable;

/**
 * Created by taras on 29.07.15.
 */
@Entity
@Table(name="users")
@JsonAutoDetect(fieldVisibility = JsonAutoDetect.Visibility.NONE)
public class User implements Serializable{

    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    @JsonProperty
    private Long id;

    @Column(name = "username", columnDefinition = "VARCHAR(50) UNIQUE")
    @JsonProperty
    private String username;

    @Column(name = "password", columnDefinition = "VARCHAR(100)")
    @JsonProperty
    private String password;

    @Column(name = "first_name", columnDefinition = "VARCHAR(255)")
    @JsonProperty
    private String firstName;

    @Column(name = "last_name", columnDefinition = "VARCHAR(255)")
    @JsonProperty
    private String lastName;

    @Column(name = "address", columnDefinition = "VARCHAR(255)")
    @JsonProperty
    private String address;

    @Column(name = "email", columnDefinition = "VARCHAR(60)")
    @JsonProperty
    private String email;

    @Column(name = "phoneNumber", columnDefinition = "VARCHAR(13)")
    @JsonProperty
    private String phoneNumber;

    @ManyToOne(targetEntity = Role.class)
    @JoinColumn(name = "role", referencedColumnName = "id")
    @JsonProperty
    private Role role;

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public String getFirstName() {
        return firstName;
    }

    public void setFirstName(String firstName) {
        this.firstName = firstName;
    }

    public String getLastName() {
        return lastName;
    }

    public void setLastName(String secondName) {
        this.lastName = secondName;
    }

    public String getAddress() {
        return address;
    }

    public void setAddress(String address) {
        this.address = address;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public String getPhoneNumber() {
        return phoneNumber;
    }

    public void setPhoneNumber(String phoneNumber) {
        this.phoneNumber = phoneNumber;
    }

    public Role getRole() {
        return role;
    }

    public void setRole(Role role) {
        this.role = role;
    }
}
