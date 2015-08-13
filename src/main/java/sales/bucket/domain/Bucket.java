package sales.bucket.domain;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;
import sales.users.domain.User;

import javax.persistence.*;
import java.util.List;

/**
 * Created by taras on 13.08.15.
 */
@Entity
@Table(name="buckets")
public class Bucket {

    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    @JsonProperty
    private Long id;

    @ManyToOne(targetEntity = User.class)
    @JoinColumn(name = "client", referencedColumnName = "id")
    @JsonProperty
    private User client;

    @OneToMany(cascade = CascadeType.ALL, mappedBy="bucket", fetch = FetchType.EAGER)
    @JsonProperty
    //@JsonIgnore
    private List<GoodInBucket> goodsInBucket;

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public User getClient() {
        return client;
    }

    public void setClient(User client) {
        this.client = client;
    }
}
