package com.pfe.testbed.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import org.junit.jupiter.api.Test;

class DiscountServiceTest {
    private final DiscountService service = new DiscountService();

    @Test
    void appliesPercentageDiscount() {
        assertEquals(80, service.discountedPrice(100, 20));
    }

    @Test
    void rejectsInvalidPercentage() {
        assertThrows(IllegalArgumentException.class, () -> service.discountedPrice(100, 101));
    }
}
