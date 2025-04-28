-- phpMyAdmin SQL Dump
-- version 5.2.1
-- https://www.phpmyadmin.net/
--
-- Servidor: 127.0.0.1
-- Tiempo de generación: 28-04-2025 a las 22:44:49
-- Versión del servidor: 10.4.32-MariaDB
-- Versión de PHP: 8.1.25

SET SQL_MODE = "NO_AUTO_VALUE_ON_ZERO";
START TRANSACTION;
SET time_zone = "+00:00";


/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8mb4 */;

--
-- Base de datos: `colegiodb`
--

DELIMITER $$
--
-- Procedimientos
--
CREATE DEFINER=`root`@`localhost` PROCEDURE `sp_LoginUsuario` (IN `p_email` VARCHAR(255), IN `p_password` VARCHAR(255), IN `p_ip` VARCHAR(45), OUT `p_resultado` BOOLEAN, OUT `p_mensaje` VARCHAR(100))   BEGIN
  DECLARE v_usuario_id INT;
  DECLARE v_estado VARCHAR(20);
  DECLARE v_intentos INT;
  DECLARE v_fecha_bloqueo DATETIME;
  DECLARE v_password_hash VARCHAR(255);
  
  -- Buscar información del usuario
  SELECT id_usuario, estado, intentos_fallidos, fecha_bloqueo, password_hash 
  INTO v_usuario_id, v_estado, v_intentos, v_fecha_bloqueo, v_password_hash
  FROM usuarios 
  WHERE email = p_email;
  
  -- Si el usuario no existe
  IF v_usuario_id IS NULL THEN
    SET p_resultado = FALSE;
    SET p_mensaje = 'Usuario no encontrado';
    INSERT INTO auditoria (operacion, descripcion, ip_address, tabla_afectada)
    VALUES ('LOGIN_FAIL', 'Intento de login con usuario inexistente', p_ip, 'Usuarios');
  ELSE
    -- Si el usuario está bloqueado
    IF v_estado = 'bloqueado' THEN
      IF TIMESTAMPDIFF(MINUTE, v_fecha_bloqueo, NOW()) >= 3 THEN
        -- Desbloquear después de 3 minutos
        UPDATE usuarios 
        SET estado = 'activo', 
            intentos_fallidos = 0,
            fecha_bloqueo = NULL
        WHERE id_usuario = v_usuario_id;
        
        INSERT INTO auditoria (usuario_afectado, operacion, descripcion, ip_address, tabla_afectada)
        VALUES (v_usuario_id, 'UPDATE', 'Desbloqueo automático por tiempo', p_ip, 'Usuarios');
      ELSE
        SET p_resultado = FALSE;
        SET p_mensaje = CONCAT('Usuario bloqueado. Intente nuevamente en ', 3 - TIMESTAMPDIFF(MINUTE, v_fecha_bloqueo, NOW()), ' minutos');
      END IF;
    END IF;
    
    -- Verificar contraseña
    IF v_password_hash = SHA2(p_password, 256) THEN
      -- Login exitoso
      UPDATE usuarios 
      SET intentos_fallidos = 0,
          ultima_ip = p_ip
      WHERE id_usuario = v_usuario_id;
      
      SET p_resultado = TRUE;
      SET p_mensaje = 'Login exitoso';
      
      INSERT INTO auditoria (usuario_afectado, operacion, descripcion, ip_address, tabla_afectada)
      VALUES (v_usuario_id, 'LOGIN', 'Inicio de sesión exitoso', p_ip, 'Usuarios');
    ELSE
      -- Contraseña incorrecta
      SET v_intentos = v_intentos + 1;
      
      IF v_intentos >= 3 THEN
        -- Bloquear después de 3 intentos fallidos
        UPDATE usuarios 
        SET estado = 'bloqueado',
            intentos_fallidos = v_intentos,
            fecha_bloqueo = NOW()
        WHERE id_usuario = v_usuario_id;
        
        SET p_resultado = FALSE;
        SET p_mensaje = 'Usuario bloqueado por 3 intentos fallidos. Espere 3 minutos.';
        
        INSERT INTO auditoria (usuario_afectado, operacion, descripcion, ip_address, tabla_afectada)
        VALUES (v_usuario_id, 'BLOQUEO', 'Bloqueo por intentos fallidos', p_ip, 'Usuarios');
        
        INSERT INTO usuarios_bloqueados (id_usuario, fecha_bloqueo, motivo)
        VALUES (v_usuario_id, NOW(), 'Bloqueo automático por 3 intentos fallidos');
      ELSE
        -- Intentos fallidos (menos de 3)
        UPDATE usuarios 
        SET intentos_fallidos = v_intentos
        WHERE id_usuario = v_usuario_id;
        
        SET p_resultado = FALSE;
        SET p_mensaje = CONCAT('Credenciales incorrectas. Intentos restantes: ', 3 - v_intentos);
        
        INSERT INTO auditoria (usuario_afectado, operacion, descripcion, ip_address, tabla_afectada)
        VALUES (v_usuario_id, 'LOGIN_FAIL', CONCAT('Intento fallido #', v_intentos), p_ip, 'Usuarios');
      END IF;
    END IF;
  END IF;
END$$

DELIMITER ;

-- --------------------------------------------------------

--
-- Estructura de tabla para la tabla `areasinstitucion`
--

CREATE TABLE `areasinstitucion` (
  `id_area` int(11) NOT NULL,
  `nombre_area` varchar(255) NOT NULL,
  `descripcion` text DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- --------------------------------------------------------

--
-- Estructura de tabla para la tabla `auditoria`
--

CREATE TABLE `auditoria` (
  `id_auditoria` int(11) NOT NULL,
  `usuario_afectado` int(11) DEFAULT NULL,
  `operacion` enum('INSERT','UPDATE','DELETE','LOGIN_FAIL','BLOQUEO','LOGIN') DEFAULT NULL,
  `descripcion` text DEFAULT NULL,
  `fecha_operacion` timestamp NOT NULL DEFAULT current_timestamp(),
  `usuario_realiza_operacion` int(11) DEFAULT NULL,
  `ip_address` varchar(45) DEFAULT NULL,
  `tabla_afectada` varchar(50) DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- --------------------------------------------------------

--
-- Estructura de tabla para la tabla `cursos`
--

CREATE TABLE `cursos` (
  `id_curso` int(11) NOT NULL,
  `nombre_curso` varchar(255) NOT NULL,
  `id_programa` int(11) DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- --------------------------------------------------------

--
-- Estructura de tabla para la tabla `docentecurso`
--

CREATE TABLE `docentecurso` (
  `id_docente_curso` int(11) NOT NULL,
  `id_usuario` int(11) DEFAULT NULL,
  `id_curso` int(11) DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- --------------------------------------------------------

--
-- Estructura de tabla para la tabla `equipostecnologicos`
--

CREATE TABLE `equipostecnologicos` (
  `id_equipo` int(11) NOT NULL,
  `nombre_equipo` varchar(255) NOT NULL,
  `marca` varchar(255) DEFAULT NULL,
  `modelo` varchar(255) DEFAULT NULL,
  `numero_serie` varchar(255) NOT NULL,
  `id_area` int(11) DEFAULT NULL,
  `estado` enum('disponible','mantenimiento','baja') DEFAULT 'disponible'
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- --------------------------------------------------------

--
-- Estructura de tabla para la tabla `eventos`
--

CREATE TABLE `eventos` (
  `id_evento` int(11) NOT NULL,
  `titulo_evento` varchar(255) NOT NULL,
  `descripcion_evento` text DEFAULT NULL,
  `fecha_evento` date NOT NULL,
  `lugar_evento` varchar(255) NOT NULL,
  `id_usuario` int(11) DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Disparadores `eventos`
--
DELIMITER $$
CREATE TRIGGER `tr_Eventos_Auditoria_Delete` AFTER DELETE ON `eventos` FOR EACH ROW BEGIN
  INSERT INTO auditoria (
    usuario_afectado,
    operacion,
    descripcion,
    usuario_realiza_operacion,
    ip_address,
    tabla_afectada
  )
  VALUES (
    OLD.id_usuario,
    'DELETE',
    CONCAT('Evento eliminado: ', OLD.titulo_evento),
    OLD.id_usuario,
    (SELECT ultima_ip FROM usuarios WHERE id_usuario = OLD.id_usuario),
    'Eventos'
  );
END
$$
DELIMITER ;
DELIMITER $$
CREATE TRIGGER `tr_Eventos_Auditoria_Insert` AFTER INSERT ON `eventos` FOR EACH ROW BEGIN
  INSERT INTO auditoria (
    usuario_afectado,
    operacion,
    descripcion,
    usuario_realiza_operacion,
    ip_address,
    tabla_afectada
  )
  VALUES (
    NEW.id_usuario,
    'INSERT',
    CONCAT('Nuevo evento creado: ', NEW.titulo_evento),
    NEW.id_usuario,
    (SELECT ultima_ip FROM usuarios WHERE id_usuario = NEW.id_usuario),
    'Eventos'
  );
END
$$
DELIMITER ;

-- --------------------------------------------------------

--
-- Estructura de tabla para la tabla `inscripciones`
--

CREATE TABLE `inscripciones` (
  `id_inscripcion` int(11) NOT NULL,
  `id_usuario` int(11) DEFAULT NULL,
  `id_curso` int(11) DEFAULT NULL,
  `fecha_inscripcion` date DEFAULT curdate()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- --------------------------------------------------------

--
-- Estructura de tabla para la tabla `notas`
--

CREATE TABLE `notas` (
  `id_nota` int(11) NOT NULL,
  `id_usuario` int(11) NOT NULL,
  `id_curso` int(11) NOT NULL,
  `calificacion` decimal(5,2) NOT NULL,
  `periodo` enum('1er trimestre','2do trimestre','3er trimestre','final') NOT NULL,
  `fecha_registro` timestamp NOT NULL DEFAULT current_timestamp(),
  `comentarios` text DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- --------------------------------------------------------

--
-- Estructura de tabla para la tabla `personal_administrativo`
--

CREATE TABLE `personal_administrativo` (
  `id_personal` int(11) NOT NULL,
  `id_usuario` int(11) NOT NULL,
  `cargo` varchar(100) NOT NULL,
  `departamento` varchar(100) NOT NULL,
  `fecha_ingreso` date NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- --------------------------------------------------------

--
-- Estructura de tabla para la tabla `programas`
--

CREATE TABLE `programas` (
  `id_programa` int(11) NOT NULL,
  `nombre_programa` varchar(255) NOT NULL,
  `descripcion` text DEFAULT NULL,
  `nivel` enum('primaria','secundaria','bachillerato') NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- --------------------------------------------------------

--
-- Estructura de tabla para la tabla `usuarios`
--

CREATE TABLE `usuarios` (
  `id_usuario` int(11) NOT NULL,
  `nombre` varchar(255) NOT NULL,
  `apellido` varchar(255) NOT NULL,
  `documento_identidad` varchar(20) NOT NULL,
  `tipo_usuario` enum('estudiante','docente','administrativo','admin') NOT NULL,
  `email` varchar(255) NOT NULL,
  `telefono` varchar(15) DEFAULT NULL,
  `direccion` varchar(255) DEFAULT NULL,
  `estado` enum('activo','inactivo','bloqueado') DEFAULT 'activo',
  `intentos_fallidos` int(11) DEFAULT 0,
  `fecha_bloqueo` datetime DEFAULT NULL,
  `fecha_registro` timestamp NOT NULL DEFAULT current_timestamp(),
  `password_hash` varchar(255) NOT NULL,
  `ultima_ip` varchar(45) DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Disparadores `usuarios`
--
DELIMITER $$
CREATE TRIGGER `tr_Usuarios_Auditoria` AFTER UPDATE ON `usuarios` FOR EACH ROW BEGIN
  IF OLD.estado != NEW.estado OR OLD.password_hash != NEW.password_hash THEN
    INSERT INTO auditoria (
      usuario_afectado,
      operacion,
      descripcion,
      usuario_realiza_operacion,
      ip_address,
      tabla_afectada
    )
    VALUES (
      NEW.id_usuario,
      'UPDATE',
      CONCAT('Modificación de usuario: ', 
        IF(OLD.estado != NEW.estado, CONCAT('Estado: ', OLD.estado, ' → ', NEW.estado, '; '), ''),
        IF(OLD.password_hash != NEW.password_hash, 'Contraseña modificada; ', '')),
      NEW.id_usuario,
      NEW.ultima_ip,
      'Usuarios'
    );
    
    -- Registrar en usuarios_bloqueados si se bloqueó
    IF NEW.estado = 'bloqueado' AND OLD.estado != 'bloqueado' THEN
      INSERT INTO usuarios_bloqueados (
        id_usuario,
        fecha_bloqueo,
        motivo
      )
      VALUES (
        NEW.id_usuario,
        NOW(),
        'Bloqueo automático por intentos fallidos'
      );
    END IF;
  END IF;
END
$$
DELIMITER ;

-- --------------------------------------------------------

--
-- Estructura de tabla para la tabla `usuarios_bloqueados`
--

CREATE TABLE `usuarios_bloqueados` (
  `id_bloqueo` int(11) NOT NULL,
  `id_usuario` int(11) NOT NULL,
  `fecha_bloqueo` datetime NOT NULL,
  `fecha_desbloqueo` datetime DEFAULT NULL,
  `motivo` text DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- --------------------------------------------------------

--
-- Estructura Stand-in para la vista `vista_docentes_cursos`
-- (Véase abajo para la vista actual)
--
CREATE TABLE `vista_docentes_cursos` (
`id_usuario` int(11)
,`docente` varchar(511)
,`nombre_curso` varchar(255)
,`nombre_programa` varchar(255)
);

-- --------------------------------------------------------

--
-- Estructura Stand-in para la vista `vista_equipos_areas`
-- (Véase abajo para la vista actual)
--
CREATE TABLE `vista_equipos_areas` (
`id_equipo` int(11)
,`nombre_equipo` varchar(255)
,`marca` varchar(255)
,`modelo` varchar(255)
,`estado` enum('disponible','mantenimiento','baja')
,`nombre_area` varchar(255)
);

-- --------------------------------------------------------

--
-- Estructura Stand-in para la vista `vista_estudiantes_cursos`
-- (Véase abajo para la vista actual)
--
CREATE TABLE `vista_estudiantes_cursos` (
`id_usuario` int(11)
,`estudiante` varchar(511)
,`nombre_programa` varchar(255)
,`nombre_curso` varchar(255)
,`fecha_inscripcion` date
);

-- --------------------------------------------------------

--
-- Estructura Stand-in para la vista `vista_notas_estudiantes`
-- (Véase abajo para la vista actual)
--
CREATE TABLE `vista_notas_estudiantes` (
`id_usuario` int(11)
,`estudiante` varchar(511)
,`nombre_curso` varchar(255)
,`calificacion` decimal(5,2)
,`periodo` enum('1er trimestre','2do trimestre','3er trimestre','final')
,`fecha_registro` timestamp
);

-- --------------------------------------------------------

--
-- Estructura Stand-in para la vista `vista_usuarios_bloqueados`
-- (Véase abajo para la vista actual)
--
CREATE TABLE `vista_usuarios_bloqueados` (
`id_usuario` int(11)
,`usuario` varchar(511)
,`email` varchar(255)
,`fecha_bloqueo` datetime
,`motivo` text
,`minutos_bloqueado` bigint(21)
);

-- --------------------------------------------------------

--
-- Estructura para la vista `vista_docentes_cursos`
--
DROP TABLE IF EXISTS `vista_docentes_cursos`;

CREATE ALGORITHM=UNDEFINED DEFINER=`root`@`localhost` SQL SECURITY DEFINER VIEW `vista_docentes_cursos`  AS SELECT `u`.`id_usuario` AS `id_usuario`, concat(`u`.`nombre`,' ',`u`.`apellido`) AS `docente`, `c`.`nombre_curso` AS `nombre_curso`, `p`.`nombre_programa` AS `nombre_programa` FROM (((`usuarios` `u` join `docentecurso` `dc` on(`u`.`id_usuario` = `dc`.`id_usuario`)) join `cursos` `c` on(`dc`.`id_curso` = `c`.`id_curso`)) join `programas` `p` on(`c`.`id_programa` = `p`.`id_programa`)) WHERE `u`.`tipo_usuario` = 'docente' ;

-- --------------------------------------------------------

--
-- Estructura para la vista `vista_equipos_areas`
--
DROP TABLE IF EXISTS `vista_equipos_areas`;

CREATE ALGORITHM=UNDEFINED DEFINER=`root`@`localhost` SQL SECURITY DEFINER VIEW `vista_equipos_areas`  AS SELECT `e`.`id_equipo` AS `id_equipo`, `e`.`nombre_equipo` AS `nombre_equipo`, `e`.`marca` AS `marca`, `e`.`modelo` AS `modelo`, `e`.`estado` AS `estado`, `a`.`nombre_area` AS `nombre_area` FROM (`equipostecnologicos` `e` join `areasinstitucion` `a` on(`e`.`id_area` = `a`.`id_area`)) ;

-- --------------------------------------------------------

--
-- Estructura para la vista `vista_estudiantes_cursos`
--
DROP TABLE IF EXISTS `vista_estudiantes_cursos`;

CREATE ALGORITHM=UNDEFINED DEFINER=`root`@`localhost` SQL SECURITY DEFINER VIEW `vista_estudiantes_cursos`  AS SELECT `u`.`id_usuario` AS `id_usuario`, concat(`u`.`nombre`,' ',`u`.`apellido`) AS `estudiante`, `p`.`nombre_programa` AS `nombre_programa`, `c`.`nombre_curso` AS `nombre_curso`, `i`.`fecha_inscripcion` AS `fecha_inscripcion` FROM (((`usuarios` `u` join `inscripciones` `i` on(`u`.`id_usuario` = `i`.`id_usuario`)) join `cursos` `c` on(`i`.`id_curso` = `c`.`id_curso`)) join `programas` `p` on(`c`.`id_programa` = `p`.`id_programa`)) WHERE `u`.`tipo_usuario` = 'estudiante' ;

-- --------------------------------------------------------

--
-- Estructura para la vista `vista_notas_estudiantes`
--
DROP TABLE IF EXISTS `vista_notas_estudiantes`;

CREATE ALGORITHM=UNDEFINED DEFINER=`root`@`localhost` SQL SECURITY DEFINER VIEW `vista_notas_estudiantes`  AS SELECT `u`.`id_usuario` AS `id_usuario`, concat(`u`.`nombre`,' ',`u`.`apellido`) AS `estudiante`, `c`.`nombre_curso` AS `nombre_curso`, `n`.`calificacion` AS `calificacion`, `n`.`periodo` AS `periodo`, `n`.`fecha_registro` AS `fecha_registro` FROM ((`usuarios` `u` join `notas` `n` on(`u`.`id_usuario` = `n`.`id_usuario`)) join `cursos` `c` on(`n`.`id_curso` = `c`.`id_curso`)) WHERE `u`.`tipo_usuario` = 'estudiante' ;

-- --------------------------------------------------------

--
-- Estructura para la vista `vista_usuarios_bloqueados`
--
DROP TABLE IF EXISTS `vista_usuarios_bloqueados`;

CREATE ALGORITHM=UNDEFINED DEFINER=`root`@`localhost` SQL SECURITY DEFINER VIEW `vista_usuarios_bloqueados`  AS SELECT `u`.`id_usuario` AS `id_usuario`, concat(`u`.`nombre`,' ',`u`.`apellido`) AS `usuario`, `u`.`email` AS `email`, `ub`.`fecha_bloqueo` AS `fecha_bloqueo`, `ub`.`motivo` AS `motivo`, timestampdiff(MINUTE,`ub`.`fecha_bloqueo`,current_timestamp()) AS `minutos_bloqueado` FROM (`usuarios` `u` join `usuarios_bloqueados` `ub` on(`u`.`id_usuario` = `ub`.`id_usuario`)) WHERE `u`.`estado` = 'bloqueado' ;

--
-- Índices para tablas volcadas
--

--
-- Indices de la tabla `areasinstitucion`
--
ALTER TABLE `areasinstitucion`
  ADD PRIMARY KEY (`id_area`);

--
-- Indices de la tabla `auditoria`
--
ALTER TABLE `auditoria`
  ADD PRIMARY KEY (`id_auditoria`),
  ADD KEY `usuario_afectado` (`usuario_afectado`),
  ADD KEY `usuario_realiza_operacion` (`usuario_realiza_operacion`);

--
-- Indices de la tabla `cursos`
--
ALTER TABLE `cursos`
  ADD PRIMARY KEY (`id_curso`),
  ADD KEY `id_programa` (`id_programa`);

--
-- Indices de la tabla `docentecurso`
--
ALTER TABLE `docentecurso`
  ADD PRIMARY KEY (`id_docente_curso`),
  ADD KEY `id_usuario` (`id_usuario`),
  ADD KEY `id_curso` (`id_curso`);

--
-- Indices de la tabla `equipostecnologicos`
--
ALTER TABLE `equipostecnologicos`
  ADD PRIMARY KEY (`id_equipo`),
  ADD UNIQUE KEY `numero_serie` (`numero_serie`),
  ADD KEY `id_area` (`id_area`);

--
-- Indices de la tabla `eventos`
--
ALTER TABLE `eventos`
  ADD PRIMARY KEY (`id_evento`),
  ADD KEY `id_usuario` (`id_usuario`);

--
-- Indices de la tabla `inscripciones`
--
ALTER TABLE `inscripciones`
  ADD PRIMARY KEY (`id_inscripcion`),
  ADD KEY `id_usuario` (`id_usuario`),
  ADD KEY `id_curso` (`id_curso`);

--
-- Indices de la tabla `notas`
--
ALTER TABLE `notas`
  ADD PRIMARY KEY (`id_nota`),
  ADD KEY `id_usuario` (`id_usuario`),
  ADD KEY `id_curso` (`id_curso`);

--
-- Indices de la tabla `personal_administrativo`
--
ALTER TABLE `personal_administrativo`
  ADD PRIMARY KEY (`id_personal`),
  ADD KEY `id_usuario` (`id_usuario`);

--
-- Indices de la tabla `programas`
--
ALTER TABLE `programas`
  ADD PRIMARY KEY (`id_programa`);

--
-- Indices de la tabla `usuarios`
--
ALTER TABLE `usuarios`
  ADD PRIMARY KEY (`id_usuario`),
  ADD UNIQUE KEY `documento_identidad` (`documento_identidad`),
  ADD UNIQUE KEY `email` (`email`);

--
-- Indices de la tabla `usuarios_bloqueados`
--
ALTER TABLE `usuarios_bloqueados`
  ADD PRIMARY KEY (`id_bloqueo`),
  ADD KEY `id_usuario` (`id_usuario`);

--
-- AUTO_INCREMENT de las tablas volcadas
--

--
-- AUTO_INCREMENT de la tabla `areasinstitucion`
--
ALTER TABLE `areasinstitucion`
  MODIFY `id_area` int(11) NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT de la tabla `auditoria`
--
ALTER TABLE `auditoria`
  MODIFY `id_auditoria` int(11) NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT de la tabla `cursos`
--
ALTER TABLE `cursos`
  MODIFY `id_curso` int(11) NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT de la tabla `docentecurso`
--
ALTER TABLE `docentecurso`
  MODIFY `id_docente_curso` int(11) NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT de la tabla `equipostecnologicos`
--
ALTER TABLE `equipostecnologicos`
  MODIFY `id_equipo` int(11) NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT de la tabla `eventos`
--
ALTER TABLE `eventos`
  MODIFY `id_evento` int(11) NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT de la tabla `inscripciones`
--
ALTER TABLE `inscripciones`
  MODIFY `id_inscripcion` int(11) NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT de la tabla `notas`
--
ALTER TABLE `notas`
  MODIFY `id_nota` int(11) NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT de la tabla `personal_administrativo`
--
ALTER TABLE `personal_administrativo`
  MODIFY `id_personal` int(11) NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT de la tabla `programas`
--
ALTER TABLE `programas`
  MODIFY `id_programa` int(11) NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT de la tabla `usuarios`
--
ALTER TABLE `usuarios`
  MODIFY `id_usuario` int(11) NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT de la tabla `usuarios_bloqueados`
--
ALTER TABLE `usuarios_bloqueados`
  MODIFY `id_bloqueo` int(11) NOT NULL AUTO_INCREMENT;

--
-- Restricciones para tablas volcadas
--

--
-- Filtros para la tabla `auditoria`
--
ALTER TABLE `auditoria`
  ADD CONSTRAINT `auditoria_ibfk_1` FOREIGN KEY (`usuario_afectado`) REFERENCES `usuarios` (`id_usuario`),
  ADD CONSTRAINT `auditoria_ibfk_2` FOREIGN KEY (`usuario_realiza_operacion`) REFERENCES `usuarios` (`id_usuario`);

--
-- Filtros para la tabla `cursos`
--
ALTER TABLE `cursos`
  ADD CONSTRAINT `cursos_ibfk_1` FOREIGN KEY (`id_programa`) REFERENCES `programas` (`id_programa`);

--
-- Filtros para la tabla `docentecurso`
--
ALTER TABLE `docentecurso`
  ADD CONSTRAINT `docentecurso_ibfk_1` FOREIGN KEY (`id_usuario`) REFERENCES `usuarios` (`id_usuario`),
  ADD CONSTRAINT `docentecurso_ibfk_2` FOREIGN KEY (`id_curso`) REFERENCES `cursos` (`id_curso`);

--
-- Filtros para la tabla `equipostecnologicos`
--
ALTER TABLE `equipostecnologicos`
  ADD CONSTRAINT `equipostecnologicos_ibfk_1` FOREIGN KEY (`id_area`) REFERENCES `areasinstitucion` (`id_area`);

--
-- Filtros para la tabla `eventos`
--
ALTER TABLE `eventos`
  ADD CONSTRAINT `eventos_ibfk_1` FOREIGN KEY (`id_usuario`) REFERENCES `usuarios` (`id_usuario`);

--
-- Filtros para la tabla `inscripciones`
--
ALTER TABLE `inscripciones`
  ADD CONSTRAINT `inscripciones_ibfk_1` FOREIGN KEY (`id_usuario`) REFERENCES `usuarios` (`id_usuario`),
  ADD CONSTRAINT `inscripciones_ibfk_2` FOREIGN KEY (`id_curso`) REFERENCES `cursos` (`id_curso`);

--
-- Filtros para la tabla `notas`
--
ALTER TABLE `notas`
  ADD CONSTRAINT `notas_ibfk_1` FOREIGN KEY (`id_usuario`) REFERENCES `usuarios` (`id_usuario`),
  ADD CONSTRAINT `notas_ibfk_2` FOREIGN KEY (`id_curso`) REFERENCES `cursos` (`id_curso`);

--
-- Filtros para la tabla `personal_administrativo`
--
ALTER TABLE `personal_administrativo`
  ADD CONSTRAINT `personal_administrativo_ibfk_1` FOREIGN KEY (`id_usuario`) REFERENCES `usuarios` (`id_usuario`);

--
-- Filtros para la tabla `usuarios_bloqueados`
--
ALTER TABLE `usuarios_bloqueados`
  ADD CONSTRAINT `usuarios_bloqueados_ibfk_1` FOREIGN KEY (`id_usuario`) REFERENCES `usuarios` (`id_usuario`);
COMMIT;

/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
