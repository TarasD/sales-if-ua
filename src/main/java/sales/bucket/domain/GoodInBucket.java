package sales.bucket.domain;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;
import sales.goods.domain.Good;
import sales.users.domain.User;

import javax.persistence.*;
import java.util.Date;

/**
 * Created by taras on 13.08.15.
 */
@Entity
@Table(name="goodInBucket")
public class GoodInBucket {

    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    @JsonProperty
    private Long id;

    @ManyToOne(targetEntity = Bucket.class)
    @JoinColumn(name = "bucket", referencedColumnName = "id")
    @JsonIgnore
    private Bucket bucket;

    @ManyToOne(targetEntity = Good.class)
    @JoinColumn(name = "good", referencedColumnName = "id")
    @JsonProperty
    private Good good;

    @Column
    @JsonProperty
    private double price;

    @Column
    @JsonProperty
    private int quantity;

    @Column
    @JsonProperty
    private Date date;

    @PrePersist
    private void onCreateGoodInBucketInstance() {
        date = new Date();
    }

    @ManyToOne(targetEntity = User.class)
    @JoinColumn(name = "shop", referencedColumnName = "id")
    @JsonProperty
    private User shop;

    public GoodInBucket() {
    }

    public GoodInBucket(Bucket bucket, Good good, int price, int quantity, User shop) {
        this.bucket = bucket;
        this.good = good;
        this.price = price;
        this.quantity = quantity;
        this.shop = shop;
    }

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public Bucket getBucket() {
        return bucket;
    }

    public void setBucket(Bucket bucket) {
        this.bucket = bucket;
    }

    public Good getGood() {
        return good;
    }

    public void setGood(Good good) {
        this.good = good;
    }

    public double getPrice() {
        return price;
    }

    public void setPrice(double price) {
        this.price = price;
    }

    public int getQuantity() {
        return quantity;
    }

    public void setQuantity(int quantity) {
        this.quantity = quantity;
    }

    public Date getDate() {
        return date;
    }

    public void setDate(Date date) {
        this.date = date;
    }

    public User getShop() {
        return shop;
    }

    public void setShop(User shop) {
        this.shop = shop;
    }
}
