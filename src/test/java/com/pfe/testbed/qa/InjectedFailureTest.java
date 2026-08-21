package com.pfe.testbed.qa;

import static org.junit.jupiter.api.Assertions.assertEquals;
import com.pfe.testbed.service.DiscountService;
import org.junit.jupiter.api.Test;

class InjectedFailureTest {
    private final DiscountService service = new DiscountService();

    @Test
    void qaT01ExpectedFailure() {
        assertEquals(70, service.discountedPrice(100, 20));
    }

    @Test
    void qaT02ExpectedFailure() {
        assertEquals(95, service.discountedPrice(100, 10));
    }
}
