package hyphen.ctink;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.EnableScheduling;

@SpringBootApplication
@EnableScheduling
public class CtinkApplication {

	public static void main(String[] args) {
		SpringApplication.run(CtinkApplication.class, args);
	}

}
