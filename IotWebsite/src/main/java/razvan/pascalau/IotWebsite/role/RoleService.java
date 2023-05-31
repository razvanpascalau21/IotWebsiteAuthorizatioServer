package razvan.pascalau.IotWebsite.role;

import lombok.AllArgsConstructor;
import org.springframework.stereotype.Service;
import razvan.pascalau.IotWebsite.user.User;
import razvan.pascalau.IotWebsite.user.UserRepository;

import java.util.List;
import java.util.Objects;
import java.util.Optional;

@Service
@AllArgsConstructor
public class RoleService {
    private final RoleRepository roleRepository;
    private final UserRepository userRepository;

    public String addRole(Role role) {
        Optional<Role> role1=roleRepository.findByNameRole(role.getNameRole());
        if(role1.isPresent()){
            throw new IllegalStateException("Role "+role.getNameRole()+" exist!");
        }
        roleRepository.save(role);
        return "Success!";
    }

    public List<Role> getAllRole(){
        return roleRepository.findAll();
    }


    public String addToleToUser(String role, String username) {
        Optional<Role> role1=roleRepository.findByNameRole(role);
        if(!role1.isPresent()){
            throw new IllegalStateException("Role "+role+" doesn't exist!");
        }
        User user=userRepository.findByEmail(username);
        if(Objects.isNull(user)){
            throw new IllegalStateException("User "+username+"doesn't exist!");
        }
        user.getRole().add(role1.orElseThrow(()->new IllegalStateException("Error!")));
        userRepository.save(user);
        return "Success!";
    }
}
