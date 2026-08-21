package com.pfe.testbed.service;

import org.springframework.stereotype.Service;

@Service
public class DiscountService {
    public int discountedPrice(int price, int percentage) {
        if (price < 0 || percentage < 0 || percentage > 100) {
            throw new IllegalArgumentException("Invalid discount input");
        }
        return price - (price * percentage / 100);
    }
}
