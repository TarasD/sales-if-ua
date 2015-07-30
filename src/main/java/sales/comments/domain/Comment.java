package sales.comments.domain;

import com.fasterxml.jackson.annotation.JsonAutoDetect;
import com.fasterxml.jackson.annotation.JsonProperty;

import javax.persistence.*;
import java.io.Serializable;
import java.util.Date;

@Entity
@Table(name = "comments")
@JsonAutoDetect(fieldVisibility = JsonAutoDetect.Visibility.NONE)
public class Comment implements Serializable {

    @Id
    @Column(name = "id")
    @GeneratedValue(strategy = GenerationType.AUTO)
    @JsonProperty
    private Long id;

    @Column(name = "userId")
    @JsonProperty
    private Long userId;

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

    public Comment(Long id, Long userId, int goodId, double rating, String commentText, Date creationDate) {
        this.id = id;
        this.userId = userId;
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

    public Long getUserId() {
        return userId;
    }

    public void setUserId(Long userId) {
        this.userId = userId;
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

    @Override
    public String toString() {
        return String.format
                ("Comment [id=%d, goodId='%d']:\n'%s';\n",
                        id, goodId, commentText);
    }
}