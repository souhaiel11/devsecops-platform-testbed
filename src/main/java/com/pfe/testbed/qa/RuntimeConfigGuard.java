package com.pfe.testbed.qa;

import org.springframework.boot.CommandLineRunner;
import org.springframework.stereotype.Component;

@Component
public class RuntimeConfigGuard implements CommandLineRunner {
    @Override
    public void run(String... args) {
        if (System.getenv("TESTBED_REQUIRED_CONFIG") == null) {
            throw new IllegalStateException("QA_R01_REQUIRED_RUNTIME_CONFIG_MISSING");
        }
    }
}
