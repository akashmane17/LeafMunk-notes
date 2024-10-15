package com.secure.notes.controllers;

import com.secure.notes.ApiResponse;
import com.secure.notes.models.AppRole;
import com.secure.notes.models.Role;
import com.secure.notes.models.User;
import com.secure.notes.repositories.RoleRepository;
import com.secure.notes.repositories.UserRepository;
import com.secure.notes.security.jwt.JwtUtils;
import com.secure.notes.security.request.ForgotPasswordRequest;
import com.secure.notes.security.request.LoginRequest;
import com.secure.notes.security.request.ResetPasswordRequset;
import com.secure.notes.security.request.SignupRequest;
import com.secure.notes.security.response.LoginResponse;
import com.secure.notes.security.response.MessageResponse;
import com.secure.notes.security.response.UserInfoResponse;
import com.secure.notes.security.services.UserDetailsImpl;
import com.secure.notes.services.TotpService;
import com.secure.notes.services.UserService;
import com.secure.notes.util.AuthUtil;
import com.warrenstrange.googleauth.GoogleAuthenticatorKey;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDate;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    @Autowired
    JwtUtils jwtUtils;

    @Autowired
    AuthenticationManager authenticationManager;

    @Autowired
    UserRepository userRepository;

    @Autowired
    RoleRepository roleRepository;

    @Autowired
    PasswordEncoder encoder;

    @Autowired
    UserService userService;

    @Autowired
    AuthUtil authUtil;

    @Autowired
    TotpService totpService;

    @PostMapping("/public/signin")
    public ResponseEntity<ApiResponse> authenticateUser(@RequestBody LoginRequest loginRequest, HttpServletResponse response) {
        Authentication authentication;
        try {
            authentication = authenticationManager
                    .authenticate(new UsernamePasswordAuthenticationToken(loginRequest.getUsername(), loginRequest.getPassword()));
        } catch (AuthenticationException exception) {
            Map<String, Object> map = new HashMap<>();
            map.put("message", "Bad credentials");
            map.put("status", false);
            return new ResponseEntity<>(new ApiResponse<>(404, "user not found", map), HttpStatus.NOT_FOUND);
        }

//      Set the authentication
        SecurityContextHolder.getContext().setAuthentication(authentication);

        UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();

        String jwtToken = jwtUtils.generateTokenFromUsername(userDetails);

        // Collect roles from the UserDetails
        List<String> roles = userDetails.getAuthorities().stream()
                .map(item -> item.getAuthority())
                .collect(Collectors.toList());


        User user = userService.findByUsername(userDetails.getUsername());

        UserInfoResponse userResponse = new UserInfoResponse(
                user.getUserName(),
                user.getEmail(),
                user.isAccountNonLocked(),
                user.isAccountNonExpired(),
                user.isCredentialsNonExpired(),
                user.isEnabled(),
                user.getCredentialsExpiryDate(),
                user.getAccountExpiryDate(),
                user.isTwoFactorEnabled(),
                roles
        );

        // Set JWT in a cookie with manual SameSite setting
        Cookie jwtCookie = jwtUtils.createJwtCookie(jwtToken);
        response.addCookie(jwtCookie);

        // Manually add the SameSite attribute
        response.addHeader("Set-Cookie", "jwtToken=" + jwtToken + "; Path=/; HttpOnly; SameSite=Lax");

        // Return the response entity with the JWT token included in the response body
        return ResponseEntity.ok(new ApiResponse<>(200, "Login successfull", userResponse));
    }

    @PostMapping("/logout")
    public ResponseEntity<ApiResponse> logout(HttpServletResponse response) {
        // Clear the JWT cookie by setting its max age to 0
        Cookie jwtCookie = new Cookie("jwtToken", null);
        jwtCookie.setPath("/");
        jwtCookie.setHttpOnly(true);
        jwtCookie.setMaxAge(0); // This will delete the cookie
        jwtCookie.setSecure(true); // Set to true if using HTTPS
        response.addCookie(jwtCookie);

        response.addHeader("Set-Cookie", "jwtToken=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0; Secure");

        return ResponseEntity.ok(new ApiResponse<>(200, "Logout successfull", null));
    }


    @PostMapping("/public/signup")
    public ResponseEntity<?> registerUser(@Valid @RequestBody SignupRequest signUpRequest) {
        if (userRepository.existsByUserName(signUpRequest.getUsername())) {
            return ResponseEntity.badRequest().body(new MessageResponse("Error: Username is already taken!"));
        }

        if (userRepository.existsByEmail(signUpRequest.getEmail())) {
            return ResponseEntity.badRequest().body(new MessageResponse("Error: Email is already in use!"));
        }

        // Create new user's account
        User user = new User(signUpRequest.getUsername(),
                signUpRequest.getEmail(),
                encoder.encode(signUpRequest.getPassword()));

        Set<String> strRoles = signUpRequest.getRole();
        Role role;

        if (strRoles == null || strRoles.isEmpty()) {
            role = roleRepository.findByRoleName(AppRole.ROLE_USER)
                    .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
        } else {
            String roleStr = strRoles.iterator().next();
            if (roleStr.equals("admin")) {
                role = roleRepository.findByRoleName(AppRole.ROLE_ADMIN)
                        .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
            } else {
                role = roleRepository.findByRoleName(AppRole.ROLE_USER)
                        .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
            }

            user.setAccountNonLocked(true);
            user.setAccountNonExpired(true);
            user.setCredentialsNonExpired(true);
            user.setEnabled(true);
            user.setCredentialsExpiryDate(LocalDate.now().plusYears(1));
            user.setAccountExpiryDate(LocalDate.now().plusYears(1));
            user.setTwoFactorEnabled(false);
            user.setSignUpMethod("email");
        }
        user.setRole(role);
        userRepository.save(user);

        MessageResponse message = new MessageResponse("User registered successfully!");
        return ResponseEntity.ok(new ApiResponse<>(200, "User registered successfully!", null));
    }

    @PostMapping("/public/forgot-password")
    public ResponseEntity<ApiResponse> forgotPassword(@Valid @RequestBody ForgotPasswordRequest request) {
        try {
            System.out.println("Forgot Password");
            userService.generatePasswordResetToken(request.getEmail());
            return ResponseEntity.ok(new ApiResponse(200, "Password reset email sent.", null));

        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(new ApiResponse(500, "Error sending password reset email", null));
        }
    }

    @PostMapping("/public/reset-password")
    public ResponseEntity<ApiResponse> resetPassword(@Valid @RequestBody ResetPasswordRequset requset) {
        try {
            userService.resetPassword(requset.getToken(), requset.getNewPassword());
            return ResponseEntity.ok(new ApiResponse(200, "Password reset successfully.", null));
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(new ApiResponse(400, e.getMessage(), null));
        }
    }

    @GetMapping("/user")
    public ResponseEntity<ApiResponse> getUserDetails(@AuthenticationPrincipal UserDetails userDetails) {
        User user = userService.findByUsername(userDetails.getUsername());

        List<String> roles = userDetails.getAuthorities().stream()
                .map(item -> item.getAuthority())
                .collect(Collectors.toList());

        UserInfoResponse response = new UserInfoResponse(
                user.getUserName(),
                user.getEmail(),
                user.isAccountNonLocked(),
                user.isAccountNonExpired(),
                user.isCredentialsNonExpired(),
                user.isEnabled(),
                user.getCredentialsExpiryDate(),
                user.getAccountExpiryDate(),
                user.isTwoFactorEnabled(),
                roles
        );

        return ResponseEntity.ok().body(new ApiResponse(200, "User fetched", response));
    }

    @GetMapping("/username")
    public ResponseEntity<ApiResponse> currentUserName(@AuthenticationPrincipal UserDetails userDetails) {
        String username = (userDetails != null) ? userDetails.getUsername() : "";

        return ResponseEntity.ok((new ApiResponse<>(200, "Username fetched", Map.of("username", username))));
    }

    // 2FA Authentitcation
    @PostMapping("/enable-2fa")
    public ResponseEntity<ApiResponse> enable2FA() {
        Long userId = authUtil.loggedInuserId();
        GoogleAuthenticatorKey secret = userService.generate2FASecret(userId);
        String qrCodeUrl = totpService.getQrCodeUrl(secret, userService.getUserById(userId).getUserName());

        return ResponseEntity.ok(new ApiResponse<>(200, "2FA Enabled", Map.of("qrCode-url", qrCodeUrl)));
    }

    @PostMapping("/disable-2fa")
    public ResponseEntity<ApiResponse> disable2FA() {
        Long userId = authUtil.loggedInuserId();
        userService.disable2FA(userId);
        return ResponseEntity.ok(new ApiResponse(200, "2FA Disabled", null));
    }

    @PostMapping("/verify-2fa")
    public ResponseEntity<ApiResponse> verfiy2FA(@RequestParam int code) {
        Long userId = authUtil.loggedInuserId();
        boolean isValid = userService.validate2FA(userId, code);

        if(isValid) {
            userService.enable2FA(userId);
            return ResponseEntity.ok(new ApiResponse(200, "2FA Verified", null));
        } else {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(new ApiResponse(403, "Invalid 2FA Code", null));
        }
    }

    @GetMapping("/user/2fa-status")
    public ResponseEntity<ApiResponse> get2FAStatus() {
        User user = authUtil.loggedInuser();
        if(user != null) {
            return ResponseEntity.ok().body(new ApiResponse<>(200, "User 2FA status fetched", Map.of("is2faEnabled", user.isTwoFactorEnabled())));
        } else {
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body(new ApiResponse(404, "User Not Found", null));
        }
    }

    @PostMapping("/public/verify-2fa-login")
    public ResponseEntity<ApiResponse> verify2FALogin(@RequestParam int code, @RequestParam String jwtToken) {
        String username = jwtUtils.getUserNameFromJwtToken(jwtToken);
        User user = userService.findByUsername(username);
        boolean isValid = userService.validate2FA(user.getUserId(), code);

        if(user != null) {
            return ResponseEntity.ok().body(new ApiResponse(200,"2FA Verified", null));
        } else {
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body(new ApiResponse(404, "Invalid 2FA Code", null));
        }
    }
}
