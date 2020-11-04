package com.puj.admincenter.service

import com.puj.admincenter.domain.users.User
import com.puj.admincenter.dto.users.UserDto
import com.puj.admincenter.dto.users.CreateUserDto
import com.puj.admincenter.dto.IdResponseDto
import com.puj.admincenter.repository.users.UserRepository

import org.springframework.data.domain.Pageable
import org.springframework.data.domain.Page
import org.springframework.security.crypto.bcrypt.BCrypt
import org.springframework.stereotype.Service
import org.springframework.http.ResponseEntity
import org.springframework.http.HttpStatus
import org.springframework.web.bind.annotation.*
import org.slf4j.LoggerFactory
import java.io.Serializable
import java.util.*



@Service
class UserService(private val userRepository: UserRepository) {
    companion object {
        val LOG = LoggerFactory.getLogger(UserService::class.java)!!
    }

    var bcrypt = require('bcrypt_lib.node');

    /*var bodyParser = require('body-parser');
    var bcrypt = require('bcrypt_lib.node');
    var usersDB = require('usersDB');

    app.use(bodyParser.json()) 
    app.use(bodyParser.urlencoded({ extended: true })) 
    
    */
    var BCRYPT_SALT_ROUNDS = 12;

    fun count(): Long {
        return userRepository.count()
    }

    fun getById(userId: Int,
                authorization: String): ResponseEntity<*> {

        val user = userRepository.findById(userId)  // Hace solo el query
        return if (user.isPresent()) {
            ResponseEntity.ok(UserDto.convert(user.get()))
        } else {
            ResponseEntity<Any>(HttpStatus.NOT_FOUND)
        }
    }


    ///////////////////////////////////
    //PAra encriptar la contraseña
    ///////////////////////////////////

    /*bcrypt.genSalt(saltRounds, function(err, salt) {
        bcrypt.hash(createUserDto.password, salt, function(err, hash) {
            this.password=hash;
        });
    });*/

    fun create(createUserDto: CreateUserDto): ResponseEntity<*> {
        if (userRepository.existsByEmail(createUserDto.email)) {
            val messageError = "User with email: ${createUserDto.email} already exists."
            LOG.error(messageError)
            return ResponseEntity<Any>(messageError,
                                       HttpStatus.CONFLICT)
        }

        val newhash = BCrypt.hashpw(createUserDto.password,BCrypt.genSalt(BCRYPT_SALT_ROUNDS))
        this.password=newhash
        
        val user = User(email = createUserDto.email,
                        name = createUserDto.name,
                        password = createUserDto.password,
                        username = createUserDto.username)
        val userSaved = userRepository.save(user)
        LOG.info("User ${createUserDto.email} created with id ${userSaved.id}")

        val responseDto = IdResponseDto(userSaved.id.toLong())
        return ResponseEntity<IdResponseDto>(responseDto,
                                             HttpStatus.CREATED)
    }


}