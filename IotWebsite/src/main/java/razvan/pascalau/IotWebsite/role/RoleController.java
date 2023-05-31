package razvan.pascalau.IotWebsite.role;

import lombok.AllArgsConstructor;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("api/role")
@AllArgsConstructor
public class RoleController {
    private final RoleService roleService;

    @PostMapping(path = "/save")
    public String addRole(@RequestBody Role role){
        return roleService.addRole(role);
    }

    @GetMapping
    public List<Role> getAllRole(){
        return roleService.getAllRole();
    }

    @PostMapping(path = "/add/user")
    public String addRoleToUser(@RequestBody AddRoleUserForm roleUserForm){
        return roleService.addToleToUser(roleUserForm.getRole(),roleUserForm.getUsername());
    }
}
