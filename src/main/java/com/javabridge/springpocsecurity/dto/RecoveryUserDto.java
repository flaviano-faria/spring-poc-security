package com.javabridge.springpocsecurity.dto;

import com.javabridge.springpocsecurity.entities.Role;

import java.util.List;

public record RecoveryUserDto(

        Long id,
        String email,
        List<Role> roles

) {
}
