package com.pfe.testbed.web;

import com.pfe.testbed.service.DiscountService;
import java.util.Map;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class CalculatorController {
    private final DiscountService discountService;

    public CalculatorController(DiscountService discountService) {
        this.discountService = discountService;
    }

    @GetMapping("/api/discount")
    public Map<String, Integer> discount(@RequestParam int price, @RequestParam int percentage) {
        return Map.of("result", discountService.discountedPrice(price, percentage));
    }
}
