package lonewolf.myboard.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import lonewolf.myboard.config.JwtTokenProvider;
import lonewolf.myboard.dto.JwtTokenDto;
import lonewolf.myboard.dto.SignUpDto;
import lonewolf.myboard.entity.Member;
import lonewolf.myboard.repository.MemberRepository;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
@Transactional(readOnly = true)
@Slf4j
public class MemberService {
    private static final String MEMBER_ALREADY_EXISTS = "이미 존재하는 회원입니다.";

    private final PasswordEncoder passwordEncoder;
    private final MemberRepository memberRepository;
    private final AuthenticationManager authenticationManager;
    private final JwtTokenProvider jwtTokenProvider;

    @Transactional
    public JwtTokenDto signIn(String username, String password) {
        log.info("Attempting to sign in user: {}", username);

        UsernamePasswordAuthenticationToken authenticationToken =
                new UsernamePasswordAuthenticationToken(username, password);

        Authentication authentication =
                authenticationManager.authenticate(authenticationToken);

        JwtTokenDto jwtToken = jwtTokenProvider.generateToken(authentication);
        log.info("Generated JWT token for user: {}", username);

        return jwtToken;
    }

    @Transactional
    public Member signUp(SignUpDto signUpDto) {
        if (memberRepository.existsByUsername(signUpDto.getUsername())) {
            log.warn("Attempted to sign up with existing username: {}", signUpDto.getUsername());
            throw new IllegalStateException(MEMBER_ALREADY_EXISTS);
        }

        String encodedPassword = encodePassword(signUpDto.getPassword());
        signUpDto.setPassword(encodedPassword);

        Member member = saveMember(signUpDto);
        log.info("Successfully signed up user: {}", member.getUsername());

        return member;
    }

    private String encodePassword(String password) {
        return passwordEncoder.encode(password);
    }

    private Member saveMember(SignUpDto signUpDto) {
        Member member = signUpDto.toMember();
        return memberRepository.save(member);
    }
}
