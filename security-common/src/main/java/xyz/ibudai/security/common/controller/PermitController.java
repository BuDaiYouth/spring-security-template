package xyz.ibudai.security.common.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/permit")
public class PermitController {

    @GetMapping("demo")
    @PreAuthorize("@ph.isPermit('ADMIN')")
    public void demo() {
        System.out.println("Permit demo");
    }
}
