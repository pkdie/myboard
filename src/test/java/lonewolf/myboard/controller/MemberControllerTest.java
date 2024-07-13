package lonewolf.myboard.controller;

import lonewolf.myboard.dto.JwtTokenDto;
import lonewolf.myboard.dto.SignUpDto;
import lonewolf.myboard.entity.Member;
import lonewolf.myboard.entity.Role;
import lonewolf.myboard.service.MemberService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.security.servlet.SecurityAutoConfiguration;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import java.util.List;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.BDDMockito.given;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@WebMvcTest(value = MemberController.class, excludeAutoConfiguration = SecurityAutoConfiguration.class)
class MemberControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @MockBean
    private MemberService memberService;
    private Member member;
    private JwtTokenDto jwtTokenDto;

    @BeforeEach
    void setUp() {

        member = Member.builder()
                .username("testuser")
                .password("password")
                .nickname("nickname")
                .email("testuser@example.com")
                .address("address")
                .phone("1234567890")
                .roles(List.of(Role.USER))
                .build();

        jwtTokenDto = JwtTokenDto.builder()
                .grantType("Bearer")
                .accessToken("testToken")
                .refreshToken("testRefreshToken")
                .build();
    }

    @Test
    void signUp_ShouldReturnCreated() throws Exception {
        given(memberService.signUp(any(SignUpDto.class))).willReturn(member);

        mockMvc.perform(post("/members/sign_up")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"testuser\"" +
                                ",\"password\":\"password\"" +
                                ",\"nickname\":\"nickname\"" +
                                ",\"email\":\"testuser@example.com\"" +
                                ",\"address\":\"address\"" +
                                ",\"phone\":\"1234567890\"}"))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.username").value("testuser"));
    }

    @Test
    void signUp_ShouldReturnInternalServerError() throws Exception {
        given(memberService.signUp(any(SignUpDto.class))).willThrow(new RuntimeException("Error"));

        mockMvc.perform(post("/members/sign_up")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"testuser\"" +
                                ",\"password\":\"password\"" +
                                ",\"nickname\":\"nickname\"" +
                                ",\"email\":\"testuser@example.com\"" +
                                ",\"address\":\"address\"" +
                                ",\"phone\":\"1234567890\"}"))
                .andExpect(status().isInternalServerError());
    }

    @Test
    void signIn_ShouldReturnOk() throws Exception {
        given(memberService.signIn(eq("testuser"), eq("password"))).willReturn(jwtTokenDto);

        mockMvc.perform(post("/members/sign_in")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"testuser\",\"password\":\"password\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accessToken").value("testToken"));
    }

    @Test
    void signIn_ShouldReturnUnauthorized() throws Exception {
        given(memberService.signIn(eq("testuser"), eq("password"))).willThrow(new RuntimeException("Unauthorized"));

        mockMvc.perform(post("/members/sign_in")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"testuser\",\"password\":\"password\"}"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void test_ShouldReturnOk() throws Exception {
        mockMvc.perform(post("/members/test"))
                .andExpect(status().isOk())
                .andExpect(content().string("success"));
    }

    @Test
    void admin_ShouldReturnOk() throws Exception {
        mockMvc.perform(post("/members/admin"))
                .andExpect(status().isOk())
                .andExpect(content().string("admin"));
    }
}
