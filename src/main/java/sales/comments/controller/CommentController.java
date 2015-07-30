package sales.comments.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;
import sales.comments.domain.Comment;
import sales.comments.service.ICommentService;

import java.util.List;

@RestController
@RequestMapping("/comment")
public class CommentController {

    @Autowired
    private ICommentService commentService;

    public CommentController() {}

    @RequestMapping(value = "/add",
            method = RequestMethod.POST,
            consumes="application/json",
            produces = "application/json")
    @ResponseStatus(HttpStatus.CREATED)
    public Comment addComment(@RequestBody Comment comment) {
        return commentService.addComment(comment);
    }

    @RequestMapping(value = "/all",
            method = RequestMethod.GET,
            produces = "application/json")
    public List<Comment> getCommentsByGoodId(@RequestParam(value = "goodId") int goodId) {
        return commentService.getCommentsByGoodId(goodId);
    }

    @RequestMapping(value = "/remove",
            method = RequestMethod.DELETE,
            produces = "application/json")
    public void removeCommentById(@RequestParam(value = "commentId") Long commentId) {
        commentService.removeCommentById(commentId);
    }
}
