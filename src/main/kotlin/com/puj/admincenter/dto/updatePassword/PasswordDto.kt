package com.puj.admincenter.dto.updatePassword

data class UpdatePasswordDto(
    val username: String,
    val password: String,    
    val newpassword: String
)

