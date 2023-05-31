package razvan.pascalau.IotWebsite.role;

import com.fasterxml.jackson.annotation.JsonIgnore;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import razvan.pascalau.IotWebsite.user.User;

import java.util.HashSet;
import java.util.Set;

@Entity
@Table(name = "roles")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class Role {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    @Column(nullable = false)
    private String nameRole;
    @JsonIgnore
    @ManyToMany(mappedBy = "role")
    private Set<User> user=new HashSet<>();

    public Role(String nameRole) {
        this.nameRole = nameRole;
    }
}
