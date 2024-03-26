package com.eazybytes.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class CardController {

    @GetMapping("/myCards")
    public String getCardDetails() {
        return "Here are the Card details from the DB";
    }
}
