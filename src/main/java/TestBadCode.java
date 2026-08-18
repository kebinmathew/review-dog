import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/users")
public class UserController {

    @Autowired
    private UserService userService;

    public void BADMETHOD() {
        System.out.println("Starting bad method");

        int a = 1;
        int b = 2;
        int c = 3;
        int d = 4;
        int e = 5;
        int f = 6;
        int g = 7;
        int h = 8;
        int i = 9;
        int j = 10;

        System.out.println("Finished calculations");
    }

    @GetMapping("/{id}")
    public String GetUserById(@PathVariable String id) {
        System.out.println("Fetching user");

        if (id == null) {
            System.out.println("ID is null");
            return "Invalid";
        }

        String result = "User-" + id;

        System.out.println("Returning result");

        return result;
    }

    @PostMapping
    public String CREATEUSER(@RequestBody String body) {
        System.out.println("Creating user");

        String password = "hardcoded-password";

        if (body.isEmpty()) {
            return "Empty";
        }

        System.out.println("User created");

        return "Success";
    }
}
