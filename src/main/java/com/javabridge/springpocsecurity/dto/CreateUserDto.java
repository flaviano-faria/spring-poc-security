package com.javabridge.springpocsecurity.dto;

import com.javabridge.springpocsecurity.enums.RoleName;

public record CreateUserDto(

        String email,
        String password,
        RoleName role

) {
}
