package lonewolf.myboard.dto;

import lombok.Builder;
import lombok.Getter;
import lombok.Setter;
import lombok.ToString;
import lonewolf.myboard.entity.Member;
import lonewolf.myboard.entity.Role;

import java.util.List;

@Getter
@Setter
@ToString
@Builder
public class SignUpDto {

    private String username;

    private String password;

    private String nickname;

    private String email;

    private String address;

    private String phone;

    public Member toMember(SignUpDto this) {
        List<Role> role = List.of(Role.USER);
        return Member.builder()
                .username(username)
                .password(password)
                .nickname(nickname)
                .email(email)
                .address(address)
                .phone(phone)
                .roles(role)
                .build();
    }
}
