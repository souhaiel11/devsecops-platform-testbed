package com.pfe.testbed.web;

import org.springframework.http.MediaType;
import org.springframework.util.HtmlUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class SearchController {
    @GetMapping(value = "/search", produces = MediaType.TEXT_HTML_VALUE)
    public String search(@RequestParam(defaultValue = "") String q) {
        return "<html><body>Search: " + HtmlUtils.htmlEscape(q) + "</body></html>";
    }
}
