package com.secure.notes.controllers;

import com.secure.notes.ApiResponse;
import com.secure.notes.models.Note;
import com.secure.notes.services.NoteService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/notes")
public class NoteController {

    @Autowired
    private NoteService noteService;

    @PostMapping
    public ResponseEntity<ApiResponse> createNote(@RequestBody String content,
                                                  @AuthenticationPrincipal UserDetails userDetails) {
        String username = userDetails.getUsername();
        System.out.println("USER DETAILS: " + username);
        Note note = noteService.createNoteForUser(username, content);
        return ResponseEntity.ok(new ApiResponse(200, "Note created", note));
    }

    @GetMapping
    public ResponseEntity<ApiResponse> getUserNotes(@AuthenticationPrincipal UserDetails userDetails) {
        String username = userDetails.getUsername();
        System.out.println("USER DETAILS: " + username);
        List<Note> notes = noteService.getNotesForUser(username);
        return ResponseEntity.ok(new ApiResponse(200, "Notes fetched", notes));
    }

    @PutMapping("/{noteId}")
    public ResponseEntity<ApiResponse> updateNote(@PathVariable Long noteId,
                                                  @RequestBody String content,
                                                  @AuthenticationPrincipal UserDetails userDetails) {
        String username = userDetails.getUsername();
        Note note = noteService.updateNoteForUser(noteId, content, username);
        return ResponseEntity.ok(new ApiResponse(200, "Note created", note));
    }

    @DeleteMapping("/{noteId}")
    public ResponseEntity<ApiResponse> deleteNote(@PathVariable Long noteId,
                           @AuthenticationPrincipal UserDetails userDetails) {
        String username = userDetails.getUsername();
        noteService.deleteNoteForUser(noteId, username);
        return ResponseEntity.ok(new ApiResponse(200, "Note deleted", null));
    }
}
