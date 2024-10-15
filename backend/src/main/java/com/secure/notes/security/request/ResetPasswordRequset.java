package com.secure.notes.security.request;

import jakarta.validation.constraints.NotBlank;
import lombok.Data;

@Data
public class ResetPasswordRequset {
    @NotBlank
    private String newPassword;

    @NotBlank
    private String token;
}
