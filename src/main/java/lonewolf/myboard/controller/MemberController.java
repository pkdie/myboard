package lonewolf.myboard.controller;

import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import lonewolf.myboard.dto.JwtTokenDto;
import lonewolf.myboard.dto.SignInDto;
import lonewolf.myboard.dto.SignUpDto;
import lonewolf.myboard.entity.Member;
import lonewolf.myboard.service.MemberService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;


@Slf4j
@RestController
@RequiredArgsConstructor
@RequestMapping("/members")
@Validated
public class MemberController {

    private final MemberService memberService;

    @PostMapping("/sign_up")
    public ResponseEntity<Member> signUp(@Valid @RequestBody SignUpDto signUpDto) {
        try {
            Member member = memberService.signUp(signUpDto);
            log.info("New member signed up: {}", member.getUsername());
            return new ResponseEntity<>(member, HttpStatus.CREATED);
        } catch (Exception e) {
            log.error("Sign up error: {}", e.getMessage());
            return new ResponseEntity<>(HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    @PostMapping("/sign_in")
    public ResponseEntity<JwtTokenDto> signIn(@Valid @RequestBody SignInDto signInDto) {
        try {
            String username = signInDto.getUsername();
            String password = signInDto.getPassword();
            JwtTokenDto jwtTokenDto = memberService.signIn(username, password);
            log.info("Member signed in: {}", username);
            return new ResponseEntity<>(jwtTokenDto, HttpStatus.OK);
        } catch (Exception e) {
            log.error("Sign in error: {}", e.getMessage());
            return new ResponseEntity<>(HttpStatus.UNAUTHORIZED);
        }
    }

    @PostMapping("/test")
    public ResponseEntity<String> test() {
        log.info("Test endpoint called");
        return new ResponseEntity<>("success", HttpStatus.OK);
    }

    @PostMapping("/admin")
    public ResponseEntity<String> admin() {
        log.info("Admin endpoint called");
        return new ResponseEntity<>("admin", HttpStatus.OK);
    }
}
