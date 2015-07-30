package sales.payment.paypal.domain;

import com.fasterxml.jackson.annotation.JsonAutoDetect;
import com.fasterxml.jackson.annotation.JsonProperty;

import javax.persistence.*;

/**
 * Created by volodya on 28.07.15.
 */
@Entity
@Table(name = "paypal")
@JsonAutoDetect(fieldVisibility = JsonAutoDetect.Visibility.ANY)
public class Paypal {

    @Id
    @GeneratedValue(strategy= GenerationType.AUTO)
    @JsonProperty("id")
    int id;

    @Column(name = "clientId")
    @JsonProperty("clientId")
    String clientId;

    @Column(name = "secret")
    @JsonProperty("secret")
    String secret;

    public int getId() {
        return id;
    }

    public void setId(int id) {
        this.id = id;
    }

    public String getClientId() {
        return clientId;
    }

    public void setClientId(String clientId) {
        this.clientId = clientId;
    }

    public String getSecret() {
        return secret;
    }

    public void setSecret(String secret) {
        this.secret = secret;
    }
}
