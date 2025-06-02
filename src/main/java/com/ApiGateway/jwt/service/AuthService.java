package com.ApiGateway.jwt.service;

import com.ApiGateway.jwt.dto.*;
import com.ApiGateway.jwt.model.Usuario;
import com.ApiGateway.jwt.repository.UsuarioRepository;
import com.ApiGateway.jwt.security.JwtUtil;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.*;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final UsuarioRepository usuarioRepository;
    private final AuthenticationManager authManager;
    private final JwtUtil jwtUtil;

    public AuthResponse login(LoginRequest request) {
        authManager.authenticate(
                new UsernamePasswordAuthenticationToken(request.getNombreUsuario(), request.getContrasena()));

        Usuario usuario = usuarioRepository.findByNombreUsuario(request.getNombreUsuario())
                .orElseThrow();

        if (!"activo".equalsIgnoreCase(usuario.getEstado())) {
            throw new BadCredentialsException("Usuario inactivo");
        }

        String token = jwtUtil.generateToken(usuario.getNombreUsuario(), usuario.getRol());
        return new AuthResponse(token, usuario.getNombreUsuario(), usuario.getRol());
    }
}
