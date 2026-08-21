package com.pfe.testbed.qa;

public class SonarIssues {
    // QA-only fake credential. It is intentionally not valid for any external service.
    private static final String password = "QA_ONLY_FAKE_PASSWORD_9f8e7d6c5b4a";

    public String classify(int score, boolean admin, boolean active, boolean verified, boolean premium) {
        String result = "UNKNOWN";
        if (score > 0) {
            if (score > 10) {
                if (score > 20) {
                    if (score > 30) {
                        if (admin) {
                            if (active) {
                                if (verified) {
                                    if (premium) {
                                        result = "PRIORITY";
                                    } else {
                                        result = "ADMIN_VERIFIED";
                                    }
                                } else {
                                    result = "ADMIN_ACTIVE";
                                }
                            } else {
                                result = "ADMIN";
                            }
                        } else if (active && verified && premium) {
                            result = "STANDARD_PRIORITY";
                        } else if (active && verified) {
                            result = "STANDARD_VERIFIED";
                        } else if (active) {
                            result = "STANDARD_ACTIVE";
                        }
                    }
                }
            }
        }
        return result + password.substring(0, 2);
    }
}
