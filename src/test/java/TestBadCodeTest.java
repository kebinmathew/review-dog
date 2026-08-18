import org.junit.Test;
import org.junit.FixMethodOrder;
import org.junit.runners.MethodSorters;
import org.springframework.boot.test.context.SpringBootTest;

// Rule 16.3: Non-deterministic order dependence annotation
// Rule 16.5: Reserve @SpringBootTest
@SpringBootTest
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class TestBadCodeTest {

    @Test
    public void testMethod() throws InterruptedException {
        // Rule 16.3: Thread.sleep
        Thread.sleep(1000);

        // Rule 16.4: Manual domain entity instantiation
        Proposal proposal = new Proposal();
        Sponsor sponsor = new Sponsor();
    }
}

class Proposal {}
class Sponsor {}
