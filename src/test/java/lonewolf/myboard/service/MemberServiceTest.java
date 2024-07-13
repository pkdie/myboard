package lonewolf.myboard.service;

import lonewolf.myboard.config.JwtTokenProvider;
import lonewolf.myboard.dto.JwtTokenDto;
import lonewolf.myboard.dto.SignUpDto;
import lonewolf.myboard.entity.Member;
import lonewolf.myboard.repository.MemberRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;


class MemberServiceTest {

    @InjectMocks
    private MemberService memberService;

    @Mock
    private MemberRepository memberRepository;

    @Mock
    private PasswordEncoder passwordEncoder;

    @Mock
    private AuthenticationManager authenticationManager;

    @Mock
    private JwtTokenProvider jwtTokenProvider;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
    }

    @Test
    void testSignIn() {
        String username = "testUser";
        String password = "testPassword";
        UsernamePasswordAuthenticationToken authenticationToken =
                new UsernamePasswordAuthenticationToken(username, password);

        Authentication authentication = mock(Authentication.class);

        when(authenticationManager.authenticate(authenticationToken))
                .thenReturn(authentication);
        when(jwtTokenProvider.generateToken(authentication))
                .thenReturn(new JwtTokenDto(
                        "bearer",
                        "accessToken",
                        "refreshToken"));

        JwtTokenDto result = memberService.signIn(username, password);

        assertNotNull(result);
        assertEquals("bearer", result.getGrantType());
        assertEquals("accessToken", result.getAccessToken());
        assertEquals("refreshToken", result.getRefreshToken());

        verify(authenticationManager).authenticate(any(UsernamePasswordAuthenticationToken.class));
        verify(jwtTokenProvider).generateToken(authentication);
    }

    @Test
    void testSignUp() {
        SignUpDto signUpDto = SignUpDto.builder()
                .username("newUser")
                .password("newPassword")
                .email("newEmail")
                .phone("010-1234-5678")
                .nickname("newNickname")
                .build();

        when(memberRepository.existsByUsername(signUpDto.getUsername())).thenReturn(false);
        when(passwordEncoder.encode(signUpDto.getPassword())).thenReturn("encodedPassword");
        when(memberRepository.save(any(Member.class))).thenAnswer(invocation -> invocation.getArgument(0));

        Member result = memberService.signUp(signUpDto);

        assertNotNull(result);
        assertEquals("newUser", result.getUsername());
        assertEquals("encodedPassword", result.getPassword());
        assertEquals("newEmail", result.getEmail());
        assertEquals("010-1234-5678", result.getPhone());
        assertEquals("newNickname", result.getNickname());

        verify(memberRepository).existsByUsername(signUpDto.getUsername());
        verify(memberRepository).save(any(Member.class));

        ArgumentCaptor<String> argumentCaptor = ArgumentCaptor.forClass(String.class);
        verify(passwordEncoder).encode(argumentCaptor.capture());
        assertEquals("newPassword", argumentCaptor.getValue());

    }

    @Test
    void testSignUp_UserAlreadyExists() {
        SignUpDto signUpDto = SignUpDto.builder()
                .username("existingUser")
                .password("password")
                .email("email")
                .nickname("nickname")
                .phone("010-1234-5678")
                .build();

        when(memberRepository.existsByUsername(signUpDto.getUsername())).thenReturn(true);

        IllegalStateException exception =
                assertThrows(IllegalStateException.class, () -> memberService.signUp(signUpDto));

        assertEquals("이미 존재하는 회원입니다.", exception.getMessage());

        verify(memberRepository).existsByUsername(signUpDto.getUsername());
        verify(passwordEncoder, never()).encode(anyString());
        verify(memberRepository, never()).save(any(Member.class));
    }
}
