package com.puj.admincenter.service

import com.puj.admincenter.domain.users.User
import com.puj.admincenter.dto.login.LoginDto
import com.puj.admincenter.dto.login.TokenDto
import com.puj.admincenter.repository.users.UserRepository


import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;

import org.springframework.beans.factory.annotation.Value
import org.springframework.http.ResponseEntity
import org.springframework.http.HttpStatus
import org.springframework.security.crypto.bcrypt.BCrypt
import org.springframework.stereotype.Service
import java.util.stream.Collectors
import org.slf4j.LoggerFactory
import java.util.Calendar
import java.util.*


@Service
class UpdatePasswordService(val userRepository: UserRepository) {
    companion object {
        val loggerUp = LoggerFactory.getLogger(UpdatePasswordService::class.java)!!
    }

    var bcrypt = require('bcrypt_lib.node');
    var BCRYPT_SALT_ROUNDS = 12;

    /*var bodyParser = require('body-parser');
    var bcrypt = require('bcrypt');
    var usersDB = require('usersDB');

    app.use(bodyParser.json()) 
    app.use(bodyParser.urlencoded({ extended: true })) 
    var BCRYPT_SALT_ROUNDS = 12;*/

    @Value(value = "\${jwt.secret}")
    private val jwtSecret: String? = null

    @Value(value = "\${jwt.expiration:5}")
    private val jwtExpiration: Long = 5


    ///////////////////////////////////
    //PAra encriptar la contraseña
    ///////////////////////////////////

    /*bcrypt.genSalt(saltRounds, function(err, salt) {
        bcrypt.hash(loginDto.password, salt, function(err, hash) {
            this.password=hash;
        });
    });*/

    fun UpdatePassword(loginDto: LoginDto): ResponseEntity<*> {


        val newhash = BCrypt.hashpw(passwordDto.password,BCrypt.genSalt(BCRYPT_SALT_ROUNDS))
        this.password=newhash

        val newhash2 = BCrypt.hashpw(passwordDto.newpassword,BCrypt.genSalt(BCRYPT_SALT_ROUNDS))
        

        val user = userRepository.findUserByUserAndPassword(loginDto.username,
                                                            loginDto.password)
        return if (user != null) {
            loggerUp.info("found user $user")

            val newPasswordSaved = userRepository.UpdatePasswordSave(newhash2)

           

            
        } else {
            val message = "the user does not exist or is not enabled" 
            loggerUp.error(message)
            ResponseEntity<String>(message,
                                   HttpStatus.NOT_FOUND)
        }
    }

    
}