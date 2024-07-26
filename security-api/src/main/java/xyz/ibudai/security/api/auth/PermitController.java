package xyz.ibudai.security.api.auth;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/permit")
public class PermitController {

    @GetMapping("demo")
    @PreAuthorize("@ph.isPermit('USER')")
    public String demo() {
        return "Permit demo";
    }
}
