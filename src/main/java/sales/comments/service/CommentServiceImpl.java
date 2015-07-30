package sales.comments.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import sales.comments.domain.Comment;
import sales.comments.repository.ICommentRepository;

import java.util.List;

@Service
@Transactional
public class CommentServiceImpl implements ICommentService {

    @Autowired
    private ICommentRepository commentRepository;

    @Override
    public Comment addComment(Comment comment) {
        return commentRepository.save(comment);
    }

    @Override
    public List<Comment> getCommentsByGoodId(int goodId) {
        return commentRepository.findByGoodIdOrderByCreationDateDesc(goodId);
    }

    @Override
    public void removeCommentById(Long id) {
        commentRepository.removeById(id);
    }
}
