package razvan.pascalau.IotWebsite.user;

import lombok.AllArgsConstructor;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("api/user")
@AllArgsConstructor
public class UserController {
    private final UserService userService;

    @PostMapping(path = "/save")
    public String addUser(@RequestBody UserModel userModel){
        userService.addUser(userModel);
        return "Success!";
    }

    @GetMapping
    public List<User> getAllUsers(){
        return userService.getAllUsers();
    }
}
