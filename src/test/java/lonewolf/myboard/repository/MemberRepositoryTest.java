package lonewolf.myboard.repository;

import lonewolf.myboard.config.JpaConfig;
import lonewolf.myboard.entity.Member;
import lonewolf.myboard.entity.Role;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.jdbc.AutoConfigureTestDatabase;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.context.annotation.Import;
import org.springframework.dao.DataIntegrityViolationException;

import java.util.Optional;
import java.util.Collections;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

@DataJpaTest
@Import(JpaConfig.class)
@AutoConfigureTestDatabase(replace = AutoConfigureTestDatabase.Replace.NONE)
public class MemberRepositoryTest {

    @Autowired
    private MemberRepository memberRepository;

    private Member member;

    @BeforeEach
    public void setUp() {
        member = Member.builder()
                .username("testuser")
                .password("password")
                .nickname("testnickname")
                .email("testuser@example.com")
                .address("123 Test St")
                .phone("123-456-7890")
                .roles(Collections.singletonList(Role.USER))
                .build();
        memberRepository.save(member);
    }

    @Test
    public void whenFindByUsername_thenReturnMember() {
        Optional<Member> foundMember = memberRepository.findByUsername("testuser");
        assertThat(foundMember.isPresent()).isTrue();
        assertThat(foundMember.get().getUsername()).isEqualTo("testuser");
    }

    @Test
    public void whenExistsByUsername_thenReturnTrue() {
        boolean exists = memberRepository.existsByUsername("testuser");
        assertThat(exists).isTrue();
    }

    @Test
    public void whenExistsByUsername_thenReturnFalse() {
        boolean exists = memberRepository.existsByUsername("nonexistentuser");
        assertThat(exists).isFalse();
    }

    @Test
    public void whenSaveDuplicateUsername_thenThrowException() {
        Member duplicateMember = Member.builder()
                .username("testuser")
                .password("newpassword")
                .nickname("newnickname")
                .email("newuser@example.com")
                .address("124 Test St")
                .phone("987-654-3210")
                .roles(Collections.singletonList(Role.USER))
                .build();

        assertThrows(DataIntegrityViolationException.class, () -> {
            memberRepository.saveAndFlush(duplicateMember);
        });
    }
}
