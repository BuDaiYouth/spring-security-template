package xyz.ibudai.security.common.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/free")
public class FreeController {

    @GetMapping("hello")
    public String hello() {
        return "Common data";
    }
}
