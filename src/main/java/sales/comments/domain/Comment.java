package sales.comments.domain;

import com.fasterxml.jackson.annotation.JsonAutoDetect;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.wordnik.swagger.annotations.ApiModel;
import sales.users.domain.User;

import javax.persistence.*;
import java.io.Serializable;
import java.util.Date;

@Entity
@Table(name = "comments")
@ApiModel(value = "CoommentDomain", description = "Simple Comment domain")
@JsonAutoDetect(fieldVisibility = JsonAutoDetect.Visibility.NONE)
public class Comment implements Serializable {

    @Id
    @Column(name = "id")
    @GeneratedValue(strategy = GenerationType.AUTO)
    @JsonProperty
    private Long id;

    @ManyToOne(targetEntity = User.class)
    @JoinColumn(name = "user", referencedColumnName = "id")
    @JsonProperty
    private User user;

    @Column(name = "goodId")
    @JsonProperty
    private int goodId;

    @Column(name = "rating")
    @JsonProperty
    private double rating;

    @Column(name = "commentText", columnDefinition="Text")
    @JsonProperty
    private String commentText;


    @Temporal(TemporalType.TIMESTAMP)
    @Column(name = "creationDate", nullable = false)
    @JsonProperty
    private Date creationDate;

    @PrePersist
    private void onCreateCommentInstance() {
        creationDate = new Date();
    }

    public Comment() {
    }

    public Comment(Long id, User user, int goodId, double rating, String commentText, Date creationDate) {
        this.id = id;
        this.user = user;
        this.goodId = goodId;
        this.rating = rating;
        this.commentText = commentText;
        this.creationDate = creationDate;
    }

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public User getUser() {
        return user;
    }

    public void setUser(User user) {
        this.user = user;
    }

    public int getGoodId() {
        return goodId;
    }

    public void setGoodId(int goodId) {
        this.goodId = goodId;
    }

    public double getRating() {
        return rating;
    }

    public void setRating(double rating) {
        this.rating = rating;
    }

    public String getCommentText() {
        return commentText;
    }

    public void setCommentText(String commentText) {
        this.commentText = commentText;
    }

    public Date getCreationDate() {
        return creationDate;
    }

    public void setCreationDate(Date creationDate) {
        this.creationDate = creationDate;
    }
}