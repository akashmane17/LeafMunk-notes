package com.secure.notes.controllers;

import com.secure.notes.ApiResponse;
import com.secure.notes.dtos.UserDTO;
import com.secure.notes.models.Role;
import com.secure.notes.models.User;
import com.secure.notes.repositories.RoleRepository;
import com.secure.notes.services.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/admin")
//@PreAuthorize("hasRole('ROLE_ADMIN')")
public class AdminController {

    @Autowired
    UserService userService;

    @Autowired
    RoleRepository roleRepository;

    @GetMapping("/getusers")
    public ResponseEntity<ApiResponse> getAllUsers() {
        List<User> data = userService.getAllUsers();
        return new ResponseEntity<>(new ApiResponse(200, "Users fetched successfully", data), HttpStatus.OK);

    }

    @PutMapping("/update-role")
    public ResponseEntity<ApiResponse> updateUserRole(@RequestParam Long userId,
                                                 @RequestParam String roleName) {
        userService.updateUserRole(userId, roleName);
        return ResponseEntity.ok(new ApiResponse<>(200, "User role updated", null));
    }

    @GetMapping("/user/{id}")
    public ResponseEntity<ApiResponse> getUser(@PathVariable Long id) {
        UserDTO data = userService.getUserById(id);
        return new ResponseEntity<>(new ApiResponse<>(200, "User fetched succesfully", data),
                HttpStatus.OK);
    }

    @PutMapping("/update-lock-status")
    public ResponseEntity<ApiResponse> updateAccountLockStatus(@RequestParam Long userId, @RequestParam boolean lock) {
        userService.updateAccountLockStatus(userId, lock);
        return ResponseEntity.ok(new ApiResponse(200, "User lock status updated", null));
    }

    @GetMapping("/roles")
    public ResponseEntity<ApiResponse> getAllRoles() {
        List<Role> data = roleRepository.findAll();
        return ResponseEntity.ok(new ApiResponse(200, "Roles fetched successfully", data));
    }

    @PutMapping("/update-expiry-status")
    public ResponseEntity<ApiResponse> updateAccountExpiryStatus(@RequestParam Long userId, @RequestParam boolean expire) {
        userService.updateAccountExpiryStatus(userId, expire);
        return ResponseEntity.ok(new ApiResponse(200, "Account Expiry status updated", null));
    }

    @PutMapping("/update-enabled-status")
    public ResponseEntity<ApiResponse> updateAccountEnabledStatus(@RequestParam Long userId, @RequestParam boolean enabled) {
        userService.updateAccountEnabledStatus(userId, enabled);
        return ResponseEntity.ok(new ApiResponse(200, "Account enabled status updated", null));
    }

    @PutMapping("/update-credentials-expiry-status")
    public ResponseEntity<ApiResponse> updateCredentialsExpiryStatus(@RequestParam Long userId, @RequestParam boolean expire) {
        userService.updateCredentialsExpiryStatus(userId, expire);
        return ResponseEntity.ok(new ApiResponse(200, "Credentials expiry status updated", null));
    }

    @PutMapping("/update-password")
    public ResponseEntity<ApiResponse> updatePassword(@RequestParam Long userId, @RequestParam String password) {
        try {
            userService.updatePassword(userId, password);
            return ResponseEntity.ok(new ApiResponse(200, "Password updated", null));
        } catch (RuntimeException e) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(new ApiResponse(400, e.getMessage(), null));
        }
    }
}
