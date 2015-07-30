package sales.comments.service;

import sales.comments.domain.Comment;

import java.util.List;

public interface ICommentService {

    public Comment addComment(Comment comment);

    public List<Comment> getCommentsByGoodId(int goodId);

    public void removeCommentById(Long id);

}
