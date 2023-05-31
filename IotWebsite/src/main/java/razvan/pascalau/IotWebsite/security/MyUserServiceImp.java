package razvan.pascalau.IotWebsite.security;

import lombok.AllArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import razvan.pascalau.IotWebsite.user.User;
import razvan.pascalau.IotWebsite.user.UserRepository;

import java.util.Objects;

@Service
@AllArgsConstructor
@Transactional
public class MyUserServiceImp implements UserDetailsService {
    private UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        final User user = userRepository.findByEmail(username);
        if(Objects.isNull(user)){
            throw new UsernameNotFoundException("User"+ username+" not found!");
        }
        return new MyUserDetails(user);
    }
}
