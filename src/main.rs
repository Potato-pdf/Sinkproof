use sinkproof::{hash_password, verify_password};
use std::time::Instant;
use std::io::{self, Write};

fn main() {
    println!("=== Sinkproof v1 - Sistema de Hashing de Contraseñas ===\n");
    
    loop {
        println!("\n--- Menú Principal ---");
        println!("1. Generar hash de contraseña");
        println!("2. Verificar contraseña");
        println!("3. Ver ejemplos de demostración");
        println!("4. Salir");
        print!("\nSeleccione una opción: ");
        io::stdout().flush().unwrap();
        
        let mut choice = String::new();
        io::stdin().read_line(&mut choice).unwrap();
        
        match choice.trim() {
            "1" => generar_hash(),
            "2" => verificar_contraseña(),
            "3" => mostrar_ejemplos(),
            "4" => {
                println!("\n¡Hasta luego!");
                break;
            }
            _ => println!("\n❌ Opción inválida. Intente de nuevo."),
        }
    }
}

fn generar_hash() {
    println!("\n--- Generar Hash de Contraseña ---");
    
    // Pedir contraseña
    print!("Ingrese la contraseña: ");
    io::stdout().flush().unwrap();
    let mut password = String::new();
    io::stdin().read_line(&mut password).unwrap();
    let password = password.trim();
    
    if password.is_empty() {
        println!("❌ La contraseña no puede estar vacía.");
        return;
    }
    
    // Pedir número de hilos
    print!("Número de hilos (recomendado: 2-8): ");
    io::stdout().flush().unwrap();
    let mut threads_str = String::new();
    io::stdin().read_line(&mut threads_str).unwrap();
    let threads: usize = match threads_str.trim().parse() {
        Ok(n) if n > 0 => n,
        _ => {
            println!("❌ Número de hilos inválido. Debe ser mayor a 0.");
            return;
        }
    };
    
    // Pedir memoria
    print!("Memoria en MB (recomendado: 10-100): ");
    io::stdout().flush().unwrap();
    let mut memory_str = String::new();
    io::stdin().read_line(&mut memory_str).unwrap();
    let memory_mb: usize = match memory_str.trim().parse() {
        Ok(n) if n > 0 => n,
        _ => {
            println!("❌ Memoria inválida. Debe ser mayor a 0 MB.");
            return;
        }
    };
    
    // Generar hash
    println!("\n🔄 Generando hash...");
    println!("   Parámetros: {} hilos, {} MB de memoria", threads, memory_mb);
    
    let start = Instant::now();
    match hash_password(password, threads, memory_mb) {
        Ok(hash) => {
            let duration = start.elapsed();
            let stored = hash.to_string();
            
            println!("\n✅ Hash generado exitosamente!");
            println!("⏱️  Tiempo: {:?}", duration);
            println!("\n📋 Hash para almacenar en base de datos:");
            println!("{}", stored);
            println!("\n💡 Guarde este hash de forma segura en su base de datos.");
        }
        Err(e) => {
            println!("\n❌ Error al generar hash: {}", e);
        }
    }
}

fn verificar_contraseña() {
    println!("\n--- Verificar Contraseña ---");
    
    // Pedir contraseña
    print!("Ingrese la contraseña a verificar: ");
    io::stdout().flush().unwrap();
    let mut password = String::new();
    io::stdin().read_line(&mut password).unwrap();
    let password = password.trim();
    
    // Pedir hash almacenado
    print!("Ingrese el hash almacenado: ");
    io::stdout().flush().unwrap();
    let mut stored_hash = String::new();
    io::stdin().read_line(&mut stored_hash).unwrap();
    let stored_hash = stored_hash.trim();
    
    if stored_hash.is_empty() {
        println!("❌ El hash no puede estar vacío.");
        return;
    }
    
    // Verificar
    println!("\n🔄 Verificando contraseña...");
    
    let start = Instant::now();
    match verify_password(password, stored_hash) {
        Ok(is_valid) => {
            let duration = start.elapsed();
            println!("\n⏱️  Tiempo de verificación: {:?}", duration);
            
            if is_valid {
                println!("✅ Contraseña CORRECTA - Acceso permitido");
            } else {
                println!("❌ Contraseña INCORRECTA - Acceso denegado");
            }
        }
        Err(e) => {
            println!("\n❌ Error al verificar: {}", e);
        }
    }
}

fn mostrar_ejemplos() {
    println!("\n=== Ejemplos de Demostración ===\n");
    
    let password = "mi_contraseña_super_segura";

    // Ejemplo 1: Hash básico
    println!("--- Ejemplo 1: Hash Básico ---");
    println!("Contraseña: {}", password);
    println!("Parámetros: 2 hilos, 10 MB de memoria");

    let start = Instant::now();
    let hash = hash_password(password, 2, 10).expect("Error al generar hash");
    let duration = start.elapsed();

    let stored = hash.to_string();
    println!("Hash generado en: {:?}", duration);
    println!("Hash almacenable:\n{}\n", stored);

    // Ejemplo 2: Verificación correcta
    println!("--- Ejemplo 2: Verificación Correcta ---");
    let start = Instant::now();
    let is_valid = verify_password(password, &stored).expect("Error al verificar");
    let duration = start.elapsed();

    println!("Contraseña a verificar: {}", password);
    println!("Resultado: {}", if is_valid { "✓ VÁLIDA" } else { "✗ INVÁLIDA" });
    println!("Verificado en: {:?}\n", duration);

    // Ejemplo 3: Verificación incorrecta
    println!("--- Ejemplo 3: Verificación Incorrecta ---");
    let wrong_password = "contraseña_incorrecta";
    let start = Instant::now();
    let is_valid = verify_password(wrong_password, &stored).expect("Error al verificar");
    let duration = start.elapsed();

    println!("Contraseña a verificar: {}", wrong_password);
    println!("Resultado: {}", if is_valid { "✓ VÁLIDA" } else { "✗ INVÁLIDA" });
    println!("Verificado en: {:?}\n", duration);

    // Ejemplo 4: Diferentes configuraciones
    println!("--- Ejemplo 4: Diferentes Configuraciones ---");
    
    let configs = vec![
        (2, 10),   // 2 hilos, 10 MB
        (4, 25),   // 4 hilos, 25 MB
        (8, 50),   // 8 hilos, 50 MB
    ];

    for (threads, memory) in configs {
        println!("Configuración: {} hilos, {} MB", threads, memory);
        let start = Instant::now();
        let hash = hash_password(password, threads, memory).expect("Error al generar hash");
        let duration = start.elapsed();
        println!("  Tiempo de hash: {:?}", duration);
        println!("  Hash: {}...", &hash.to_string()[..60]);
        println!();
    }

    // Ejemplo 5: Mismo password, diferentes salts
    println!("--- Ejemplo 5: Mismo Password, Diferentes Salts ---");
    let hash1 = hash_password(password, 2, 10).expect("Error");
    let hash2 = hash_password(password, 2, 10).expect("Error");
    
    println!("Hash 1: {}...", &hash1.to_string()[..60]);
    println!("Hash 2: {}...", &hash2.to_string()[..60]);
    println!("Son iguales? {}", if hash1.to_string() == hash2.to_string() { "Sí" } else { "No (Correcto!)" });
    println!("Ambos verifican correctamente? {}", 
        if verify_password(password, &hash1.to_string()).unwrap() && 
           verify_password(password, &hash2.to_string()).unwrap() { 
            "Sí (Correcto!)" 
        } else { 
            "No" 
        }
    );
    println!();

    // Ejemplo 6: Formato de almacenamiento
    println!("--- Ejemplo 6: Formato de Almacenamiento ---");
    println!("El hash se almacena en el formato:");
    println!("Sinkproof:v1:hilos:memoria_mb:salt_base64:frase_encriptada_base64");
    println!("\nEjemplo completo:");
    println!("{}", stored);
    println!("\nComponentes:");
    let parts: Vec<&str> = stored.split(':').collect();
    println!("  Nombre: {}", parts[0]);
    println!("  Versión: {}", parts[1]);
    println!("  Hilos: {}", parts[2]);
    println!("  Memoria (MB): {}", parts[3]);
    println!("  Salt (base64): {}...", &parts[4][..20]);
    println!("  Frase encriptada (base64): {}...", &parts[5][..20]);
    
    println!("\n=== Ejemplos Completados ===");
}
