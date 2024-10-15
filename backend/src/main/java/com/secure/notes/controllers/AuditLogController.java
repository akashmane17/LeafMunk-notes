package com.secure.notes.controllers;

import com.secure.notes.ApiResponse;
import com.secure.notes.models.AuditLog;
import com.secure.notes.services.AuditLogService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
@RequestMapping("/api/audit")
public class AuditLogController {
    @Autowired
    AuditLogService auditLogService;

    @GetMapping
    @PreAuthorize("hasRole('ROLE_ADMIN')")
    public ResponseEntity<ApiResponse> getAuditLogs(){

        List<AuditLog> logs = auditLogService.getAllAuditLogs();
        return ResponseEntity.ok(new ApiResponse(200, "OK", logs));
    }

    @GetMapping("/note/{id}")
    @PreAuthorize("hasRole('ROLE_ADMIN')")
    public ResponseEntity<ApiResponse> getNoteAuditLogs(@PathVariable Long id){
        List<AuditLog> logs = auditLogService.getAuditLogsForNoteId(id);
        return ResponseEntity.ok(new ApiResponse(200, "OK", logs));
    }

}
