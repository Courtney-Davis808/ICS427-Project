import ics427.Main;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;


import static org.junit.jupiter.api.Assertions.*;

public class MainTest {
    public static Main main = new Main();
    @Test
    public void addOneTest() {
        System.out.println("WHOA");
        System.out.println(main.addOne(0));
        assertEquals(1, main.addOne(0));

    }
}
