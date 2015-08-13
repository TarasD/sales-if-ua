package sales.comments.controller;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.ObjectWriter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.ContextLoader;
import org.springframework.test.context.testng.AbstractTestNGSpringContextTests;
import org.springframework.test.context.web.WebAppConfiguration;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import sales.comments.domain.Comment;
import sales.users.service.UserService;

import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@ContextConfiguration(locations =
        {
            "classpath:META-INF/applicationContext.xml",
            "classpath:test-mvc-servlet.xml"
        },
        loader = ContextLoader.class)
@WebAppConfiguration
public class TestCommentController extends AbstractTestNGSpringContextTests {

    @Autowired
    private WebApplicationContext wac;

    @Autowired
    UserService userService;

    private MockMvc mockMvc;

    private Comment comment;

    private static final int GOOD_ID = -1;
    private static final Long USER_ID = 1L;
    private static final String COMMENT_TEXT = "TEST_COMMENT_TEXT";
    private static final double RATING = 1.0;
    private static final String MAIN_URL = "/comment";
    private String commentJson;

    @BeforeMethod
    public void initMockMvc() throws JsonProcessingException {
        this.mockMvc = MockMvcBuilders.webAppContextSetup(wac).build();

        this.comment = new Comment();
        this.comment.setUser(userService.getById(USER_ID));
        this.comment.setGoodId(GOOD_ID);
        this.comment.setCommentText(COMMENT_TEXT);
        this.comment.setRating(RATING);

        ObjectWriter ow = new ObjectMapper().writer().withDefaultPrettyPrinter();
        this.commentJson = ow.writeValueAsString(this.comment);
    }

    @Test
    public void testCommentController() throws Exception {
        MvcResult result = mockMvc.perform(post(MAIN_URL)
                .content(commentJson)
                .contentType(MediaType.APPLICATION_JSON)
                .sessionAttr("comment", this.comment))
                .andExpect(status().isCreated())
                .andReturn();

        String response = result.getResponse().getContentAsString();
        Long commentId = new ObjectMapper().readValue(response, Comment.class).getId();

        mockMvc.perform(get(MAIN_URL + "/" + GOOD_ID)
                .accept(APPLICATION_JSON))
                .andExpect(status().isOk())
                .andExpect(content().contentType(APPLICATION_JSON));

        mockMvc.perform(delete(MAIN_URL + "/" + commentId))
                .andExpect(status().isOk());
    }

}
